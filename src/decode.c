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
        r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    current = next + 1;
    next = strchr(current, '.');

    if (next == NULL) /* No signature. */
    {
        if (alg != -1)
        {
            r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
            goto exit;
        }
    }

    current_length = (next != NULL ? next : (params->jwt + params->jwt_length)) - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)(&payload), &payload_length);
    if (r != L8W8JWT_SUCCESS)
    {
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
            r = L8W8JWT_BASE64_FAILURE;
            goto exit;
        }
    }

    current = next = NULL;

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
