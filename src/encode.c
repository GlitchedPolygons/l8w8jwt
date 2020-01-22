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

#include "l8w8jwt/encode.h"
#include "l8w8jwt/retcodes.h"
#include "l8w8jwt/base64.h"

#include <inttypes.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

int validate_encoding_params(struct l8w8jwt_encoding_params* params)
{
    if (params == NULL || params->secret_key == NULL || params->out == NULL || params->out_length == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    if (params->secret_key_length == 0)
    {
        return L8W8JWT_INVALID_ARG;
    }

    if ((params->additional_payload_claims != NULL && params->additional_payload_claims_count == 0))
    {
        return L8W8JWT_INVALID_ARG;
    }

    if ((params->additional_header_claims != NULL && params->additional_header_claims_count == 0))
    {
        return L8W8JWT_INVALID_ARG;
    }

    return L8W8JWT_SUCCESS;
}

static int write_header_and_payload(chillbuff* stringbuilder, struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff buff;

    r = chillbuff_init(&buff, 256, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    switch (params->alg)
    {
        case L8W8JWT_ALG_HS256:
            chillbuff_push_back(&buff, "{\"alg\":\"HS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_HS384:
            chillbuff_push_back(&buff, "{\"alg\":\"HS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_HS512:
            chillbuff_push_back(&buff, "{\"alg\":\"HS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS256:
            chillbuff_push_back(&buff, "{\"alg\":\"RS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS384:
            chillbuff_push_back(&buff, "{\"alg\":\"RS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS512:
            chillbuff_push_back(&buff, "{\"alg\":\"RS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS256:
            chillbuff_push_back(&buff, "{\"alg\":\"PS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS384:
            chillbuff_push_back(&buff, "{\"alg\":\"PS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS512:
            chillbuff_push_back(&buff, "{\"alg\":\"PS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES256:
            chillbuff_push_back(&buff, "{\"alg\":\"ES256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES384:
            chillbuff_push_back(&buff, "{\"alg\":\"ES384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES512:
            chillbuff_push_back(&buff, "{\"alg\":\"ES512\",\"typ\":\"JWT\"", 26);
            break;
        default:
            chillbuff_free(&buff);
            return L8W8JWT_INVALID_ARG;
    }

    if (params->additional_header_claims_count > 0)
    {
        chillbuff_push_back(&buff, ",", 1);
        l8w8jwt_write_claims(&buff, params->additional_header_claims, params->additional_header_claims_count);
    }

    chillbuff_push_back(&buff, "}", 1);

    char* segment;
    size_t segment_length;

    r = l8w8jwt_base64_encode(true, buff.array, buff.length, &segment, &segment_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&buff);
        return r;
    }

    chillbuff_push_back(stringbuilder, segment, segment_length);

    free(segment);
    segment = NULL;
    chillbuff_clear(&buff);

    char iatnbfexp[64];
    memset(iatnbfexp, '\0', sizeof(iatnbfexp));

    if (params->iat)
    {
        snprintf(iatnbfexp + 00, 21, "%" PRIu64 "", (uint64_t)params->iat);
    }

    if (params->nbf)
    {
        snprintf(iatnbfexp + 21, 21, "%" PRIu64 "", (uint64_t)params->nbf);
    }

    if (params->exp)
    {
        snprintf(iatnbfexp + 42, 21, "%" PRIu64 "", (uint64_t)params->exp);
    }

    struct l8w8jwt_claim claims[] = {
        // Setting l8w8jwt_claim::value_length to 0 makes the encoder use strlen, which in this case is fine.
        { .key = *(iatnbfexp + 00) ? "iat" : NULL, .key_length = 3, .value = iatnbfexp + 00, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = *(iatnbfexp + 21) ? "nbf" : NULL, .key_length = 3, .value = iatnbfexp + 21, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = *(iatnbfexp + 42) ? "exp" : NULL, .key_length = 3, .value = iatnbfexp + 42, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = params->sub ? "sub" : NULL, .key_length = 3, .value = params->sub, .value_length = params->sub_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->iss ? "iss" : NULL, .key_length = 3, .value = params->iss, .value_length = params->iss_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->aud ? "aud" : NULL, .key_length = 3, .value = params->aud, .value_length = params->aud_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->jti ? "jti" : NULL, .key_length = 3, .value = params->jti, .value_length = params->jti_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
    };

    chillbuff_push_back(&buff, "{", 1);

    l8w8jwt_write_claims(&buff, claims, sizeof(claims) / sizeof(struct l8w8jwt_claim));

    if (params->additional_payload_claims_count > 0)
    {
        chillbuff_push_back(&buff, ",", 1);
        l8w8jwt_write_claims(&buff, params->additional_payload_claims, params->additional_payload_claims_count);
    }

    chillbuff_push_back(&buff, "}", 1);

    r = l8w8jwt_base64_encode(true, buff.array, buff.length, &segment, &segment_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&buff);
        return r;
    }

    chillbuff_push_back(stringbuilder, ".", 1);
    chillbuff_push_back(stringbuilder, segment, segment_length);

    free(segment);
    chillbuff_free(&buff);

    return L8W8JWT_SUCCESS;
}

static int jwt_hs(struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff stringbuilder;

    r = chillbuff_init(&stringbuilder, 256, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    r = write_header_and_payload(&stringbuilder, params);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    uint8_t signature_bytes[64];
    const mbedtls_md_info_t* info = params->alg == L8W8JWT_ALG_HS256 ? &mbedtls_sha256_info : params->alg == L8W8JWT_ALG_HS384 ? &mbedtls_sha384_info : &mbedtls_sha512_info;

    r = mbedtls_md_hmac(info, params->secret_key, params->secret_key_length, (const unsigned char*)stringbuilder.array, stringbuilder.length, (unsigned char*)signature_bytes);
    if (r != 0)
    {
        chillbuff_free(&stringbuilder);
        return params->alg == L8W8JWT_ALG_HS256 ? L8W8JWT_HS256_SIGNATURE_FAILURE : params->alg == L8W8JWT_ALG_HS384 ? L8W8JWT_HS384_SIGNATURE_FAILURE : L8W8JWT_HS512_SIGNATURE_FAILURE;
    }

    char* signature;
    size_t signature_length;

    r = l8w8jwt_base64_encode(true, signature_bytes, 32 + (16 * params->alg), &signature, &signature_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature, signature_length);

    free(signature);

    *(params->out) = malloc(stringbuilder.length + 1);
    if (*(params->out) == NULL)
    {
        chillbuff_free(&stringbuilder);
        return L8W8JWT_OUT_OF_MEM;
    }

    *(params->out_length) = stringbuilder.length;
    (*(params->out))[stringbuilder.length] = '\0';
    memcpy(*(params->out), stringbuilder.array, stringbuilder.length);

    chillbuff_free(&stringbuilder);
    return L8W8JWT_SUCCESS;
}

static int jwt_rs(struct l8w8jwt_encoding_params* params) {}

static int jwt_ps(struct l8w8jwt_encoding_params* params) {}

static int jwt_es(struct l8w8jwt_encoding_params* params) {}

int encode(struct l8w8jwt_encoding_params* params)
{
    int r = validate_encoding_params(params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    switch (params->alg)
    {
        case L8W8JWT_ALG_HS256:
        case L8W8JWT_ALG_HS384:
        case L8W8JWT_ALG_HS512:
            return jwt_hs(params);

        case L8W8JWT_ALG_RS256:
        case L8W8JWT_ALG_RS384:
        case L8W8JWT_ALG_RS512:
            return jwt_rs(params);

        case L8W8JWT_ALG_PS256:
        case L8W8JWT_ALG_PS384:
        case L8W8JWT_ALG_PS512:
            return jwt_ps(params);

        case L8W8JWT_ALG_ES256:
        case L8W8JWT_ALG_ES384:
        case L8W8JWT_ALG_ES512:
            return jwt_es(params);

        default:
            return L8W8JWT_INVALID_ARG;
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
