/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "string.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "sgx_tcrypto.h"

/*
* Elliptic Curve Cryptography - Based on GF(p), 256 bit
*/
/* Allocates and initializes ecc context
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Output: sgx_ecc_state_handle_t *p_ecc_handle - Pointer to the handle of ECC crypto system  */
sgx_status_t sgx_ecc256_open_context_k(sgx_ecc_state_handle_t* p_ecc_handle);

/* Cleans up ecc context
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Output: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system  */
sgx_status_t sgx_ecc256_close_context_k(sgx_ecc_state_handle_t ecc_handle);

/* Populates private/public key pair - caller code allocates memory
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
*   Outputs: sgx_ec256_private_t *p_private - Pointer to the private key
*            sgx_ec256_public_t *p_public - Pointer to the public key  */
sgx_status_t sgx_ecc256_create_key_pair_k(sgx_ec256_private_t *p_private,
    sgx_ec256_public_t *p_public,
    sgx_ecc_state_handle_t ecc_handle);

/* Checks whether the input point is a valid point on the given elliptic curve
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
*           sgx_ec256_public_t *p_point - Pointer to perform validity check on - LITTLE ENDIAN
*   Output: int *p_valid - Return 0 if the point is an invalid point on ECC curve */
sgx_status_t sgx_ecc256_check_point_k(const sgx_ec256_public_t *p_point,
                                    const sgx_ecc_state_handle_t ecc_handle,
                                    int *p_valid);


/** Create an ECC public key based on a given ECC private key.
*
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS or failure as defined in sgx_error.h
*   Input: p_att_priv_key - Input private key
*   Output: p_att_pub_key - Output public key - LITTLE ENDIAN
*
*/
sgx_status_t sgx_ecc256_calculate_pub_from_priv_k(const sgx_ec256_private_t *p_att_priv_key, sgx_ec256_public_t  *p_att_pub_key);

