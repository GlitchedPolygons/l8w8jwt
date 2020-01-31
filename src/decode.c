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
#include <mbedtls/asn1write.h>

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

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)(&header), &header_length);
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
        r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
        goto exit;
    }

    current_length = (next != NULL ? next : params->jwt + params->jwt_length) - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)(&payload), &payload_length);
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

        size_t signature_cmp_length = 0;

        unsigned char signature_cmp[4096];
        memset(signature_cmp, '\0', sizeof(signature_cmp));

        switch (alg)
        {
            case L8W8JWT_ALG_HS256:
            case L8W8JWT_ALG_HS384:
            case L8W8JWT_ALG_HS512:

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

            case L8W8JWT_ALG_RS256:
            case L8W8JWT_ALG_RS384:
            case L8W8JWT_ALG_RS512:

                // TODO: rsa verification
                break;

            case L8W8JWT_ALG_PS256:
            case L8W8JWT_ALG_PS384:
            case L8W8JWT_ALG_PS512:

                // TODO: rsassa pss verification
                break;

            case L8W8JWT_ALG_ES256:
            case L8W8JWT_ALG_ES384:
            case L8W8JWT_ALG_ES512:

                // TODO: ecdsa verification
                break;

            default:
                break;
        }

        // TODO: other claims verification

        memset(key, '\0', sizeof(key));
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
    }

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
