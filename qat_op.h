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
 * @file qat_op.h
 *
 * This file provides an interface for engine operations used for both ciphers
 * and digests
 *
 *****************************************************************************/

#ifndef QAT_OP_H
# define QAT_OP_H

# include <openssl/engine.h>
# include <openssl/ssl.h>
# include <openssl/crypto.h>
# include <openssl/aes.h>

# define AES_IV_LEN                 16
# define AES_KEY_SIZE_256           32
# define AES_KEY_SIZE_128           16
# define QAT_BYTE_SHIFT             8
# define HMAC_KEY_SIZE              64
# define TLS_VIRT_HDR_SIZE          13
# define TLS_MAX_PADDING_LENGTH     255

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

# define INIT_SEQ_CLEAR_ALL_FLAGS(qctx)  ((qctx)->init_flags = 0)
# define INIT_SEQ_SET_FLAG(qctx, f)      ((qctx)->init_flags |= (f))
# define INIT_SEQ_CLEAR_FLAG(qctx, f)    ((qctx)->init_flags &= ~(f))
# define INIT_SEQ_IS_FLAG_SET(qctx,f)    ((qctx)->init_flags & (f))

/* QAT max supported pipelines may be different from
 * SSL max supported ones.
 */
# define QAT_MAX_PIPELINES   SSL_MAX_PIPELINES

/* These are QAT API operation parameters */
typedef struct qat_op_params_t {
    CpaCySymOpData op_data;
    CpaBufferList src_sgl;
    CpaBufferList dst_sgl;
    CpaFlatBuffer src_fbuf[2];
    CpaFlatBuffer dst_fbuf[2];
} qat_op_params;

#endif /* QAT_OP_H */
