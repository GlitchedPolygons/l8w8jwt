/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "l8w8jwt/decode.h"
#include "l8w8jwt/base64.h"
#include "l8w8jwt/retcodes.h"

#include <stdbool.h>
#include <inttypes.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk_internal.h>

#define L8W8JWT_MAX_KEY_SIZE 8192

static inline void md_info_from_alg(const int alg, mbedtls_md_info_t** md_info, mbedtls_md_type_t* md_type, size_t* md_length)
{
    switch (alg)
    {
        case L8W8JWT_ALG_HS256:
        case L8W8JWT_ALG_RS256:
        case L8W8JWT_ALG_PS256:
        case L8W8JWT_ALG_ES256:
            *md_length = 32;
            *md_type = MBEDTLS_MD_SHA256;
            *md_info = (mbedtls_md_info_t*)(&mbedtls_sha256_info);
            break;

        case L8W8JWT_ALG_HS384:
        case L8W8JWT_ALG_RS384:
        case L8W8JWT_ALG_PS384:
        case L8W8JWT_ALG_ES384:
            *md_length = 48;
            *md_type = MBEDTLS_MD_SHA384;
            *md_info = (mbedtls_md_info_t*)(&mbedtls_sha384_info);
            break;

        case L8W8JWT_ALG_HS512:
        case L8W8JWT_ALG_RS512:
        case L8W8JWT_ALG_PS512:
        case L8W8JWT_ALG_ES512:
            *md_length = 64;
            *md_type = MBEDTLS_MD_SHA512;
            *md_info = (mbedtls_md_info_t*)(&mbedtls_sha512_info);
            break;

        default:
            break;
    }
}

int l8w8jwt_validate_decoding_params(struct l8w8jwt_decoding_params* params)
{
    if (params == NULL || params->jwt == NULL || params->verification_key == NULL || (params->out_claims != NULL && params->out_claims_length == NULL))
    {
        return L8W8JWT_NULL_ARG;
    }

    if (params->jwt_length == 0 || params->verification_key_length == 0 || params->verification_key_length > L8W8JWT_MAX_KEY_SIZE)
    {
        return L8W8JWT_INVALID_ARG;
    }

    return L8W8JWT_SUCCESS;
}

int l8w8jwt_decode(struct l8w8jwt_decoding_params* params, enum l8w8jwt_validation_result* out)
{
    int alg = params->alg;
    enum l8w8jwt_validation_result validation_res = L8W8JWT_VALID;

    int r = l8w8jwt_validate_decoding_params(params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    if (out == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    char* header = NULL;
    size_t header_length = 0;

    char* payload = NULL;
    size_t payload_length = 0;

    uint8_t* signature = NULL;
    size_t signature_length = 0;

    char* current = params->jwt;
    char* next = strchr(params->jwt, '.');

    if (next == NULL) /* No payload. */
    {
        return L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
    }

    size_t current_length = next - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)&header, &header_length);
    if (r != L8W8JWT_SUCCESS)
    {
        if (r != L8W8JWT_OUT_OF_MEM)
            r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    current = next + 1;
    next = strchr(current, '.');

    if (next == NULL && alg != -1) /* No signature. */
    {
        r = L8W8JWT_DECODE_FAILED_MISSING_SIGNATURE;
        goto exit;
    }

    current_length = (next != NULL ? next : params->jwt + params->jwt_length) - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)&payload, &payload_length);
    if (r != L8W8JWT_SUCCESS)
    {
        if (r != L8W8JWT_OUT_OF_MEM)
            r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    if (next != NULL)
    {
        current = next + 1;
        current_length = (params->jwt + params->jwt_length) - current;

        r = l8w8jwt_base64_decode(true, current, current_length, &signature, &signature_length);
        if (r != L8W8JWT_SUCCESS)
        {
            if (r != L8W8JWT_OUT_OF_MEM)
                r = L8W8JWT_BASE64_FAILURE;
            goto exit;
        }
    }

    /* Signature verification. */
    if (signature != NULL && signature_length > 0 && alg != -1)
    {
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);

        mbedtls_entropy_context entropy;
        mbedtls_entropy_init(&entropy);

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ctr_drbg_init(&ctr_drbg);

        unsigned char key[L8W8JWT_MAX_KEY_SIZE];
        size_t key_length = params->verification_key_length;

        memset(key, '\0', sizeof(key));
        memcpy(key, params->verification_key, key_length);

        if (key[key_length - 1] != '\0')
        {
            key_length++;
        }

        size_t md_length;
        mbedtls_md_type_t md_type;
        mbedtls_md_info_t* md_info;

        md_info_from_alg(alg, &md_info, &md_type, &md_length);

        unsigned char hash[64];
        memset(hash, '\0', sizeof(hash));

        r = mbedtls_md(md_info, (const unsigned char*)params->jwt, (current - 1) - params->jwt, hash);
        if (r != L8W8JWT_SUCCESS)
        {
            r = L8W8JWT_SHA2_FAILURE;
            goto exit;
        }

        switch (alg)
        {
            case L8W8JWT_ALG_HS256:
            case L8W8JWT_ALG_HS384:
            case L8W8JWT_ALG_HS512: {

                unsigned char signature_cmp[64];
                memset(signature_cmp, '\0', sizeof(signature_cmp));

                r = mbedtls_md_hmac(md_info, key, key_length - 1, (const unsigned char*)params->jwt, (current - 1) - params->jwt, signature_cmp);
                if (r != 0)
                {
                    validation_res |= L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                r = memcmp(signature, signature_cmp, 32 + (16 * alg));
                if (r != 0)
                {
                    validation_res |= L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;
            }

            case L8W8JWT_ALG_RS256:
            case L8W8JWT_ALG_RS384:
            case L8W8JWT_ALG_RS512:

                r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                if (r != 0)
                {
                    r = L8W8JWT_KEY_PARSE_FAILURE;
                    goto exit;
                }

                r = mbedtls_pk_verify(&pk, md_type, hash, md_length, (const unsigned char*)signature, signature_length);
                if (r != 0)
                {
                    validation_res |= L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;

            case L8W8JWT_ALG_PS256:
            case L8W8JWT_ALG_PS384:
            case L8W8JWT_ALG_PS512:

                r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                if (r != 0)
                {
                    r = L8W8JWT_KEY_PARSE_FAILURE;
                    goto exit;
                }

                mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
                rsa->hash_id = md_type;
                rsa->padding = MBEDTLS_RSA_PKCS_V21;

                r = mbedtls_rsa_rsassa_pss_verify(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, md_type, md_length, hash, signature);
                if (r != 0)
                {
                    validation_res |= L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;

            case L8W8JWT_ALG_ES256:
            case L8W8JWT_ALG_ES384:
            case L8W8JWT_ALG_ES512:

                r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                if (r != 0)
                {
                    r = L8W8JWT_KEY_PARSE_FAILURE;
                    goto exit;
                }

                const size_t half_signature_length = signature_length / 2;

                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);

                mbedtls_mpi sig_r, sig_s;
                mbedtls_mpi_init(&sig_r);
                mbedtls_mpi_init(&sig_s);

                r = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(pk));
                if (r != 0)
                {
                    r = L8W8JWT_KEY_PARSE_FAILURE;
                    mbedtls_ecdsa_free(&ecdsa);
                    mbedtls_mpi_free(&sig_r);
                    mbedtls_mpi_free(&sig_s);
                    goto exit;
                }

                mbedtls_mpi_read_binary(&sig_r, signature, half_signature_length);
                mbedtls_mpi_read_binary(&sig_s, signature + half_signature_length, half_signature_length);

                r = mbedtls_ecdsa_verify(&ecdsa.grp, hash, md_length, &ecdsa.Q, &sig_r, &sig_s);
                if (r != 0)
                {
                    validation_res |= L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                }

                mbedtls_mpi_free(&sig_r);
                mbedtls_mpi_free(&sig_s);
                mbedtls_ecdsa_free(&ecdsa);
                break;

            default:
                break;
        }

        memset(key, '\0', sizeof(key));
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
    }


    // TODO: other claims verification

    r = L8W8JWT_SUCCESS;
    *out = validation_res;

exit:
    free(header);
    free(payload);
    free(signature);
    return r;
}

#ifdef __cplusplus
} // extern "C"
#endif
