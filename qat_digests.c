/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2018 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

/*
 * This file contains modified code from OpenSSL/BoringSSL used
 * in order to run certain operations in constant time.
 * It is subject to the following license:
 */

/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*****************************************************************************
 * @file qat_digests.c
 *
 * This file contains the engine implementations for digest operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_digests.h"
#include "qat_constant_time.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/async.h>
#include <openssl/lhash.h>
#include <string.h>

#define DEBUG_PPL DEBUG

#ifdef OPENSSL_ENABLE_QAT_DIGESTS
# ifdef OPENSSL_DISABLE_QAT_DIGESTS
#  undef OPENSSL_DISABLE_QAT_DIGESTS
# endif
#endif

#ifndef OPENSSL_DISABLE_QAT_DIGESTS
static int qat_digest_init(EVP_MD_CTX *ctx);
static int qat_digest_cleanup(EVP_MD_CTX *ctx);
static int qat_digest_update(EVP_MD_CTX *ctx,
                             const void *data,
                             size_t count);
static int qat_digest_final(EVP_MD_CTX *ctx,
                            unsigned char *md);
#endif

/*
 * Import from qat_ciphers.c
 *
 */
CpaStatus qat_sym_perform_op(int inst_num,
                             void *pCallbackTag,
                             const CpaCySymOpData * pOpData,
                             const CpaBufferList * pSrcBuffer,
                             CpaBufferList * pDstBuffer,
                             CpaBoolean * pVerifyResult);

/*
 * Set up the structures for the openssl interface
 */
int qat_digest_nids[] = { NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_md5 };

typedef struct _digest_info {
    const int nid;
    EVP_MD *digest;
    int result_size;
    int input_block_size;
} digest_info;

static digest_info info[] = {
  {NID_sha1,   NULL, SHA_DIGEST_LENGTH,   SHA_CBLOCK},
  {NID_sha224, NULL, SHA224_DIGEST_LENGTH, SHA256_CBLOCK},
  {NID_sha256, NULL, SHA256_DIGEST_LENGTH, SHA256_CBLOCK},
  {NID_sha384, NULL, SHA384_DIGEST_LENGTH, SHA256_CBLOCK},
  {NID_sha512, NULL, SHA512_DIGEST_LENGTH, SHA512_CBLOCK},
  {NID_md5,    NULL, MD5_DIGEST_LENGTH,    MD5_CBLOCK}
};

static const unsigned int num_cc = sizeof(info) / sizeof(digest_info);

/*
 * This structure is used by the asynchronous job tracking subsystem
 */
typedef struct {
  op_done_t done;
  qat_op_params *qop;
  int last;
} digest_op_data;

/******************************************************************************
* function:
*         qat_digest_callbackFn(void *callbackTag, CpaStatus status,
*                               const CpaCySymOp operationType, void *pOpData,
*                               CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*

* @param pCallbackTag  [IN] -  Opaque value provided by user while making
*                              individual function call. Cast to digest_op_data.
* @param status        [IN] -  Status of the operation.
* @param operationType [IN] -  Identifies the operation type requested.
* @param pOpData       [IN] -  Pointer to structure with input parameters.
* @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
* @param verifyResult  [IN] -  Unused in this implementation
*
* description:
*   Callback function used by digests. This function is called when each operation is 
*   completed. However the paused job is woken up when the final operation is completed
*   and the digest is ready to be read.
*
******************************************************************************/
void qat_digest_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType,
                           void *pOpData, CpaBufferList *pDstBuffer,
                           CpaBoolean verifyResult) {
  digest_op_data *opdata = (digest_op_data *)callbackTag;
  int i;

  if (opdata == NULL)
    return;

  if (opdata->qop != NULL) {
    /* No longer need the buffers allocated for this qop */
    QAT_QMEMFREE_BUFF(opdata->qop->src_sgl.pPrivateMetaData);
    for (i=0; i < opdata->qop->src_sgl.numBuffers; i++) {
      QAT_QMEMFREE_BUFF(opdata->qop->src_sgl.pBuffers[i].pData);
    }
    free(opdata->qop->src_sgl.pBuffers);
    free(opdata->qop);
    opdata->qop = NULL;
  }

  /* 
   * Mark job as done when all the requests have been submitted and
   * subsequently processed.
   */

  if (!opdata->last) {
    free(opdata);
  } else {
    opdata->done.flag = 1;
    if (opdata->done.job) {
      WARN("CALLBACK ON JOB COMPLETION: %p", opdata->done.job);
      qat_wake_job(opdata->done.job, 0);
    }
  }
}


/* Setup template for Session Setup Data as most of the fields
 * are constant. The constant values of some of the fields are
 * chosen for hashing operation.
 */
static const CpaCySymSessionSetupData template_ssd = {
    .sessionPriority = CPA_CY_PRIORITY_HIGH,
    .symOperation = CPA_CY_SYM_OP_HASH,
    .hashSetupData = {
                      .hashAlgorithm = CPA_CY_SYM_HASH_SHA256,
                      .hashMode = CPA_CY_SYM_HASH_MODE_PLAIN,
                      .digestResultLenInBytes = SHA256_DIGEST_LENGTH
                      },
    .algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER,
    .digestIsAppended = CPA_FALSE,
    .verifyDigest = CPA_FALSE,
    .partialsNotRequired = CPA_FALSE
};



static inline const EVP_MD *qat_digest_sw_impl(int nid)
{
    switch (nid) {
        case NID_sha1:
            return EVP_sha1();
        case NID_sha224:
            return EVP_sha224();
        case NID_sha256:
            return EVP_sha256();
        case NID_sha384:
            return EVP_sha384();
        case NID_sha512:
            return EVP_sha512();
        case NID_md5:
            return EVP_md5();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

static const EVP_MD *qat_create_digest_meth(int nid, int result_size, int input_block_size)
{
#ifndef OPENSSL_DISABLE_QAT_DIGESTS
    EVP_MD *d = NULL;
    int res = 1;

    if ((d = EVP_MD_meth_new(nid, 0)) == NULL) {
        WARN("Failed to allocate digest methods for nid %d\n", nid);
        return NULL;
    }

    res &= EVP_MD_meth_set_result_size(d, result_size);
    res &= EVP_MD_meth_set_input_blocksize(d, input_block_size);
    res &= EVP_MD_meth_set_app_datasize(d, sizeof(qat_digest_ctx));
    res &= EVP_MD_meth_set_init(d, qat_digest_init);
    res &= EVP_MD_meth_set_update(d, qat_digest_update);
    res &= EVP_MD_meth_set_final(d, qat_digest_final);
    res &= EVP_MD_meth_set_cleanup(d, qat_digest_cleanup);
    res &= EVP_MD_meth_set_flags(d, EVP_MD_FLAG_DIGALGID_ABSENT);

    if (res == 0) {
        WARN("Failed to set digest methods for nid %d\n", nid);
        EVP_MD_meth_free(d);
        d = NULL;
    }

    return d;
#else
    return qat_digest_sw_impl(nid);
#endif
}

void qat_create_digests(void) {
    int i;

    for (i = 0; i < num_cc; i++) {
        if (info[i].digest == NULL) {
            info[i].digest = (EVP_MD *)
              qat_create_digest_meth(info[i].nid, info[i].result_size, info[i].input_block_size);
        }
    }
}

void qat_free_digests(void) {
    int i;

    for (i = 0; i < num_cc; i++) {
        if (info[i].digest != NULL) {
#ifndef OPENSSL_DISABLE_QAT_DIGESTS
            EVP_MD_meth_free(info[i].digest);
#endif
            info[i].digest = NULL;
        }
    }
}

/******************************************************************************
* function:
*         qat_digests(ENGINE *e,
*                     const EVP_MD **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param cipher [IN] - digest structure pointer
* @param nids   [IN] - digest function nids
* @param nid    [IN] - digest operation id
*
* description:
*   Qat engine digest operations registrar
******************************************************************************/
int qat_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    int i;

    /* No specific digest => return a list of supported nids ... */
    if (digest == NULL) {
        *nids = qat_digest_nids;
        /* num ciphers supported (size of array/size of 1 element) */
        return (sizeof(qat_digest_nids) / sizeof(qat_digest_nids[0]));
    }

    for (i = 0; i < num_cc; i++) {
        if (nid == info[i].nid) {
            if (info[i].digest == NULL)
                qat_create_digests();
            *digest = info[i].digest;
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *digest = NULL;
    return 0;
}


#ifndef OPENSSL_DISABLE_QAT_DIGESTS

/******************************************************************************
* function:
*         qat_digest_init(EVP_MD_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the hash algorithm parameters for this EVP 
*    context.
*
******************************************************************************/
static int qat_digest_init(EVP_MD_CTX *ctx) {
    CpaCySymSessionSetupData *ssd = NULL;
    Cpa32U sctx_size = 0;
    CpaCySymSessionCtx sctx = NULL;
    CpaStatus sts = 0;
    qat_digest_ctx *qctx = NULL;
    const EVP_MD *md = NULL;

    if (ctx == NULL) {
        WARN("ctx is NULL.\n");
        return 0;
    }

    qctx = qat_digest_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        return 0;
    }

    md = EVP_MD_CTX_md(ctx);
    if (md == NULL) {
      WARN("md is NULL.\n");
      return 0;
    }

    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);

    memset(qctx, 0, sizeof(*qctx));

    qctx->digest_size = EVP_MD_meth_get_result_size(md);
    qctx->block_size = EVP_MD_meth_get_input_blocksize(md);
    qctx->qop = NULL;
    qctx->num_pkts = 0;

    ssd = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (ssd == NULL) {
        WARN("Failed to allocate session setup data\n");
        goto err;
    }

    qctx->session_data = ssd;

    /* Copy over the template for most of the values */
    memcpy(ssd, &template_ssd, sizeof(template_ssd));

    /* Set the values based on the type of this digest */
    switch (EVP_MD_CTX_type(ctx)) {
    case NID_sha1:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
      break;
    case NID_sha224:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA224;
      break;
    case NID_sha256:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
      break;
    case NID_sha384:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA384;
      break;
    case NID_sha512:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA512;
      break;
    case NID_md5:
      ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_MD5;
      break;
    default:
      WARN("Unsupported hash type: %d\n", EVP_MD_CTX_type(ctx));
      goto err;
    }
    ssd->hashSetupData.digestResultLenInBytes = qctx->digest_size;

    qctx->inst_num = get_next_inst_num();
    if (qctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get QAT Instance Handle!.\n");
        goto err;
    }

    DEBUG("inst_num = %d\n", qctx->inst_num);
    DUMP_SESSION_SETUP_DATA(ssd);
    sts = cpaCySymSessionCtxGetSize(qat_instance_handles[qctx->inst_num], ssd, &sctx_size);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        goto err;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    sctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size, __FILE__,
                                                  __LINE__);
    if (sctx == NULL) {
        WARN("QMEM alloc failed for session ctx!\n");
        goto err;
    }

    qctx->session_ctx = sctx;

    qctx->digest_buffer = (Cpa8U *) qaeCryptoMemAlloc(ssd->hashSetupData.digestResultLenInBytes,
                                                      __FILE__, __LINE__);

    if (qctx->digest_buffer == NULL) {
      WARN("QMEM alloc failed for digest buffer!\n");
      goto err;
    }

    INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_CTX_INIT);

    DEBUG("session_ctx = %p\n", qctx->session_ctx);
    /* Setting up in synchronous mode at the moment, though that's not ideal */
    sts = cpaCySymInitSession(qat_instance_handles[qctx->inst_num], qat_digest_callbackFn,
                              qctx->session_data, qctx->session_ctx);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymInitSession failed! Status = %d\n", sts);
        goto sessinit_err;
    }
    INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_SESSION_INIT);

    DEBUG_PPL("[%p] qat digest ctx %p initialised\n",ctx, qctx);
    return 1;

 sessinit_err:
    sts = cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                qctx->session_ctx);
    if (sts != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymRemoveSession FAILED, sts = %d\n", sts);
    }

 err:
    OPENSSL_free(ssd);
    qctx->session_data = NULL;
    QAT_QMEMFREE_BUFF(qctx->session_ctx);
    QAT_QMEMFREE_BUFF(qctx->digest_buffer);

    return 0;
}


/******************************************************************************
* function:
*    qat_chained_ciphers_cleanup(EVP_MD_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  hashing.
*
******************************************************************************/
static int qat_digest_cleanup(EVP_MD_CTX *ctx) {
    qat_digest_ctx *qctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 1;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        return 0;
    }

    qctx = qat_digest_data(ctx);
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        return 0;
    }

    ssd = qctx->session_data;
    if (ssd) {
        if (INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_SESSION_INIT)) {
            sts = cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                        qctx->session_ctx);
            if (sts != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymRemoveSession FAILED, sts = %d\n", sts);
                retVal = 0;
            }
        }
        QAT_QMEMFREE_BUFF(qctx->session_ctx);
        QAT_QMEMFREE_BUFF(qctx->digest_buffer);
        OPENSSL_free(ssd);
    }

    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);
    DEBUG_PPL("[%p] EVP CTX cleaned up\n", ctx);
    return retVal;
}

/******************************************************************************
* function:
*    qat_create_digest_scatter_gather_list(qat_digest_ctx *qctx,
*                                          const void *data,
*                                          size_t count,
*                                          CpaBufferList *src_sgl
*
* @param qctx    [IN]  - pointer to existing qat_digest_ctx
* @param data    [IN]  - pointer to buffer containing input data
* @param count   [IN]  - length of input data
* @param src_sgl [OUT] - pointer to existing CpaBufferList which is to be
*                        populated
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will allocate the buffers used for the digest operation.
*
******************************************************************************/
int qat_create_digest_scatter_gather_list(qat_digest_ctx *qctx,
                                          const void *data,
                                          size_t count,
                                          CpaBufferList *src_sgl) {
  Cpa32U msize;
  CpaStatus sts = 0;
  CpaFlatBuffer *src_buffers_fb = NULL;
  Cpa8U **src_buffers = NULL;
  Cpa8U *pBufferMeta = NULL;
  int n_buffers = (count + QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES - 1)/QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES;
  int i;

  memset(src_sgl, 0, sizeof(CpaBufferList));
  src_buffers = malloc(n_buffers * sizeof(Cpa8U*));

  if (src_buffers == NULL) {
    WARN("Allocation failed for source buffers array.\n");
    goto err;
  }

  memset(src_buffers, 0, n_buffers * sizeof(Cpa8U*));

  src_buffers_fb = malloc(n_buffers * sizeof(CpaFlatBuffer));

  if (src_buffers_fb == NULL) {
    WARN("Allocation failed for source buffers flatbuffer array.\n");
    goto err;
  }

  memset(src_buffers_fb, 0, n_buffers * sizeof(CpaFlatBuffer));

  for (i=0; i < n_buffers-1; i++) {
    /*
     * Allocate space for the source buffer 
     * this is memory contiguous and contains all the data provided
     */
    src_buffers[i] = qaeCryptoMemAlloc(QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES, __FILE__, __LINE__);

    if (src_buffers[i] == NULL) {
      WARN("Contiguous allocation failed for source buffer %d.\n", i);
      goto err;
    }

    /* Copy the input data into the buffer */
    memcpy(src_buffers[i], data + i*QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES, QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES);

    src_buffers_fb[i].dataLenInBytes = QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES;
    src_buffers_fb[i].pData = src_buffers[i];
  }

  {
    const int last_buffer_size = count - (n_buffers-1)*QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES;

    src_buffers[n_buffers-1] = qaeCryptoMemAlloc(last_buffer_size, __FILE__, __LINE__);
    if (src_buffers[i] == NULL) {
      WARN("Contiguous allocation failed for source buffer %d.\n", n_buffers-1);
      goto err;
    }

    memcpy(src_buffers[n_buffers-1], data + (n_buffers-1)*QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES, last_buffer_size);

    src_buffers_fb[n_buffers-1].dataLenInBytes = last_buffer_size;
    src_buffers_fb[n_buffers-1].pData = src_buffers[n_buffers-1];
  }

  /* get meta information size */
  sts = cpaCyBufferListGetMetaSize(qat_instance_handles[qctx->inst_num], n_buffers, &msize);

  if (sts != CPA_STATUS_SUCCESS) {
    WARN("cpaCyBufferListGetBufferSize failed.\n");
    goto err;
  }

  pBufferMeta = qaeCryptoMemAlloc(msize, __FILE__, __LINE__);

  if (pBufferMeta == NULL) {
    WARN("Contiguous allocation failed for sgl metadata.\n");
    goto err;
  }

  src_sgl->pBuffers = src_buffers_fb;
  src_sgl->numBuffers = n_buffers;
  src_sgl->pPrivateMetaData = pBufferMeta;

  free(src_buffers);

  return 1;

 err:

  for (i=0; i < n_buffers; i++) {
    QAT_QMEMFREE_BUFF(src_buffers[i]);
  }

  free(src_buffers);
  free(src_buffers_fb);

  return 0;
}

/******************************************************************************
* function:
*    qat_perform_digest_operation(qat_digest_ctx *qctx,
*                                 const void *data,
*                                 size_t count,
*                                 op_done_t **done)
*
* @param qctx    [IN]  - pointer to existing qat_digest_ctx
* @param data    [IN]  - pointer to buffer containing input data, if NULL will
*                        assume this is the last operation.
* @param count   [IN]  - length of input data
* @param done    [OUT] - pointer to a location to put the address of the 
*                        op_done_t object which can be monitored for when the job 
*                        is finished
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function is called whenever a digest operation (update or final) is
*   needed. In fact the first call to this method doesn't perform any actual
*   operation on the card, it just prepares one and then stores it. Subsequent
*   calls prepare the next operation and then swap it with the currently stored
*   one before performing *that* operation. Since no data is provided on the
*   final call no new operation is created and instead the previous update data
*   is sent to the card.
*
******************************************************************************/
static int qat_perform_digest_operation(qat_digest_ctx *qctx,
                                        const void *data,
                                        size_t count,
                                        op_done_t **done) {
    CpaStatus sts = 0;
    thread_local_variables_t *tlv = NULL;
    qat_op_params *qop = NULL;
    digest_op_data *op_data = NULL;

    /* If data has been provided create a buffer for it */
    if (data != NULL) {
      CpaBufferList *src_sgl = NULL;
      CpaCySymOpData *opd = NULL;

      qop = malloc(sizeof(qat_op_params));

      if (qop == NULL) {
        WARN("Failed to allocated qop structure\n");
        goto err;
      }

      memset(qop, 0, sizeof(qat_op_params));
      opd = &qop->op_data;
      src_sgl = &qop->src_sgl;

      if (!qat_create_digest_scatter_gather_list(qctx, data, count, src_sgl)) {
        WARN("Allocation of scatter gather list for data failed\n");
        goto err_after_qop_allocation;
      }

      memset(opd, 0, sizeof(CpaCySymOpData));

      opd->packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
      opd->sessionCtx = qctx->session_ctx;
      opd->hashStartSrcOffsetInBytes = 0;
      opd->messageLenToHashInBytes = count;
      opd->pDigestResult = qctx->digest_buffer;
    }

    /* Swap the newly allocated qop with the one stored in qctx */
    QAT_DIGEST_SWAP_QOP(qctx, qop);

    if (qop == NULL) {
      /* This was the first call to update for this context, but we don't know if it'll be the last, nothing can be done
         yet except registering that we will soon have operations in flight*/
      DEBUG("Storing qop for later use\n");

      /* Allocate local variables and increment jobs in flight */
      tlv = qat_check_create_local_variables();
      if (NULL == tlv) {
        WARN("could not create local variables\n");
        goto err_after_buf_allocation;
      }

      QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
      if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
          if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
            goto err_after_tlv_allocation;
          }
        }
      }

      return 1;
    } else {
      op_data = malloc(sizeof(digest_op_data));

      if (data == NULL) {
        /* This is the last packet */
        if (qctx->num_pkts == 0) {
          /* And also the first, apparently */
          qop->op_data.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        } else {
          /* But not the first */
          qop->op_data.packetType = CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL;
        }
        qat_init_op_done(&op_data->done);
        if (done != NULL)
          *done = &op_data->done;
      }

      op_data->qop = qop;
      op_data->last = (data == NULL);

      sts = qat_sym_perform_op(qctx->inst_num,
                               op_data,
                               &qop->op_data,
                               &qop->src_sgl,
                               &qop->src_sgl,
                               NULL);

      QAT_ATOMIC_INC(qctx->num_pkts);

      if (sts != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymPerformOp failed.\n");
        free(op_data);
        goto err_after_buf_allocation;
      }

      DEBUG_PPL("[%p] Updated data of length %d\n", qctx, qop->op_data.messageLenToHashInBytes);

      return 1;
    }

 err_after_tlv_allocation:
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
 err_after_buf_allocation:
    free(qop->src_sgl.pBuffers);
    QAT_QMEMFREE_BUFF(qop->src_sgl.pPrivateMetaData);
    QAT_QMEMFREE_BUFF(qop->src_sgl.pBuffers->pData);
 err_after_qop_allocation:
    free(qop);
 err:
    return 0;
}

/******************************************************************************
* function:
*    qat_digest_update(EVP_MD_CTX *ctx,
*                      const void *data,
*                      size_t count)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param data   [IN]  - input data for digest
* @param count  [IN]  - size of data
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function updates the hash with new data
*
******************************************************************************/
static int qat_digest_update(EVP_MD_CTX *ctx,
                             const void *data,
                             size_t count) {
    qat_digest_ctx *qctx = NULL;
    int retval = 1;
    op_done_t *done = NULL;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        retval = 0;
        goto err;
    }

    qctx = qat_digest_data(ctx);
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        retval = 0;
        goto err;
    }

    if (!qat_perform_digest_operation(qctx, data, count, &done)) {
      WARN("qat_perform_digest_operation failed.\n");
      retval = 0;
      goto err;
    }

 err:
    return retval;
}

/******************************************************************************
* function:
*    qat_digest_final(EVP_MD_CTX *ctx,
*                     unsigned char *md)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param md     [OUT] - digest data
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function finalises the hash and returns the digest
*
******************************************************************************/
static int qat_digest_final(EVP_MD_CTX *ctx,
                            unsigned char *md) {

  thread_local_variables_t *tlv = NULL;
  qat_digest_ctx *qctx = NULL;
  int retval = 1;
  op_done_t *done = NULL;
  int job_ret = 0;

  if (ctx == NULL) {
    WARN("ctx parameter is NULL.\n");
    retval = 0;
    goto err;
  }

  qctx = qat_digest_data(ctx);
  if (qctx == NULL) {
    WARN("qctx parameter is NULL.\n");
    retval = 0;
    goto err;
  }

  if (!qat_perform_digest_operation(qctx, NULL, 0, &done)) {
    WARN("qat_perform_digest_operation failed.\n");
    retval = 0;
    goto err;
  }

  /* If there is nothing to wait for, do not pause or yield */
  if (done->flag) {
    if (done->job != NULL) {
      qat_clear_async_event_notification();
    }
    goto end;
  }

  do {
    if (done->job != NULL) {
      /* If we get a failure on qat_pause_job then we will
         not flag an error here and quit because we have
         an asynchronous request in flight.
         We don't want to start cleaning up data
         structures that are still being used. If
         qat_pause_job fails we will just yield and
         loop around and try again until the request
         completes and we can continue. */
      WARN("ATTEMPT PAUSE OF JOB: %p", done->job);
      if ((job_ret = qat_pause_job(done->job, 0)) == 0) {
        WARN("NO PAUSE, YIELD");
        pthread_yield();
      } else {
        WARN("JOB_RET: %d", job_ret);
      }
    } else {
      pthread_yield();
    }
  } while (!done->flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

 end:
  free(done);
  memcpy(md, qctx->digest_buffer, qctx->digest_size);

 err:
  tlv = qat_check_create_local_variables();
  if (NULL == tlv) {
    WARN("could not create local variables\n");
    return 0;
  }

  QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

  return retval;
}
#endif
