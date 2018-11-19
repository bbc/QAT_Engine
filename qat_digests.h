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
 * @file qat_digests.h
 *
 * This file provides an interface for engine digest operations
 *
 *****************************************************************************/

#ifndef QAT_DIGESTS_H
# define QAT_DIGESTS_H

# include "qat_op.h"

# define qat_digest_data(ctx) \
    ((qat_digest_ctx *)EVP_MD_CTX_md_data(ctx))

/* This is an atomic swap of pointer contents */
# define QAT_DIGEST_SWAP_QOP(CTX, QOP) \
  (QOP) = __sync_lock_test_and_set(&((CTX)->qop), (QOP))

typedef struct qat_digest_ctx_t {
    /* QAT Session Params */
    int inst_num;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    int init_flags;

    /* The contiguous memory buffer to which the digest will be written */
    Cpa8U *digest_buffer;
    int digest_size;
    int block_size;

    /* Operation stored for later use */
    qat_op_params *qop;
    int num_pkts;
} qat_digest_ctx;

# define QAT_MAX_DIGEST_INPUT_BUFFER_SIZE_IN_BYTES 65536

void qat_create_digests(void);
void qat_free_digests(void);
int qat_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

#endif                          /* QAT_DIGESTS_H */
