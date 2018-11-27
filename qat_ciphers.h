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

/*****************************************************************************
 * @file qat_ciphers.h
 *
 * This file provides an interface for engine cipher operations
 *
 *****************************************************************************/

#ifndef QAT_CIPHERS_H
# define QAT_CIPHERS_H

# include "qat_op.h"

/* Use these flags to mark stages in the
 * initialisation sequence for pipes.
 */
# define INIT_SEQ_QAT_CTX_INIT      0x0001
# define INIT_SEQ_HMAC_KEY_SET      0x0002
# define INIT_SEQ_QAT_SESSION_INIT  0x0004
# define INIT_SEQ_TLS_HDR_SET       0x0008
# define INIT_SEQ_PPL_IBUF_SET      0x0100
# define INIT_SEQ_PPL_OBUF_SET      0x0200
# define INIT_SEQ_PPL_BUF_LEN_SET   0x0400
# define INIT_SEQ_PPL_AADCTR_SET    0x0800
# define INIT_SEQ_PPL_USED          0x1000

# define qat_chained_data(ctx) \
    ((qat_chained_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx))

# define QAT_COMMON_CIPHER_FLAG     EVP_CIPH_FLAG_DEFAULT_ASN1
# define QAT_CBC_FLAGS              (QAT_COMMON_CIPHER_FLAG | \
                                     EVP_CIPH_CBC_MODE | \
                                     EVP_CIPH_CUSTOM_IV)
# define QAT_CHAINED_FLAG           (QAT_CBC_FLAGS | \
                                     EVP_CIPH_FLAG_CUSTOM_CIPHER | \
                                     EVP_CIPH_FLAG_AEAD_CIPHER | \
                                     EVP_CIPH_FLAG_PIPELINE)

# define INIT_SEQ_PPL_INIT_COMPLETE  (INIT_SEQ_PPL_IBUF_SET | \
                                      INIT_SEQ_PPL_OBUF_SET | \
                                      INIT_SEQ_PPL_AADCTR_SET | \
                                      INIT_SEQ_PPL_BUF_LEN_SET)

# define TLS_HDR_SET(qctx)    ((qctx)->init_flags & INIT_SEQ_TLS_HDR_SET)

# define PIPELINE_SET(qctx) \
                     (((qctx)->init_flags & INIT_SEQ_PPL_INIT_COMPLETE) \
                       == INIT_SEQ_PPL_INIT_COMPLETE)
# define PIPELINE_NOT_SET(qctx) \
                         (((qctx)->init_flags & INIT_SEQ_PPL_INIT_COMPLETE) \
                           == 0)
# define PIPELINE_USED(qctx)  ((qctx)->init_flags & INIT_SEQ_PPL_USED)
# define PIPELINE_INCOMPLETE_INIT(qctx) \
                              (!PIPELINE_SET(qctx) && !PIPELINE_NOT_SET(qctx) \
                               && !PIPELINE_USED(qctx))
# define CLEAR_PIPELINE(qctx) \
                    do { \
                        (qctx)->init_flags &= ~(INIT_SEQ_PPL_INIT_COMPLETE); \
                        (qctx)->numpipes = 1; \
                    } while(0)

typedef struct qat_chained_ctx_t {
    /* Crypto */
    unsigned char *hmac_key;
# ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    /* Pointer for context data that will be used by
     * Small packet offload feature. */
    void *sw_ctx_data;
# endif
    /* QAT Session Params */
    int inst_num;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    int init_flags;

    unsigned int aad_ctr;
    char aad[QAT_MAX_PIPELINES][TLS_VIRT_HDR_SIZE];

    /* QAT Operation Params are required per pipe in the pipeline.
     * Hence this is a pointer to a dynamically allocated array with
     * length equal to QAT_MAX_PIPELINES if pipes are used else 1.
     */
    qat_op_params *qop;
    unsigned int qop_len;

    /* Pipeline related Data */
    unsigned char **p_in;
    unsigned char **p_out;
    size_t  *p_inlen;
    unsigned int numpipes;
    unsigned int npipes_last_used;
    unsigned long total_op;
} qat_chained_ctx;

void qat_create_ciphers(void);
void qat_free_ciphers(void);
int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                int nid);
# ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
int qat_pkt_threshold_table_set_threshold(const char *cipher_name,
                                          int threshold);
# endif
#endif                          /* QAT_CIPHERS_H */
