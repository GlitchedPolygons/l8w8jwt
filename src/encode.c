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

#include <inttypes.h>
#include "l8w8jwt/encode.h"
#include "l8w8jwt/retcodes.h"
#include "l8w8jwt/base64.h"

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

int encode(chillbuff* stringbuilder, int alg, struct l8w8jwt_encoding_params* params)
{
    if (stringbuilder == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    if (alg < 0 || alg > 8)
    {
        return L8W8JWT_INVALID_ARG;
    }

    int r = validate_encoding_params(params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    chillbuff buff;
    r = chillbuff_init(&buff, 256, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    switch (alg)
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
        snprintf(iatnbfexp + 00, 21, "%"PRIu64"", (uint64_t)params->iat);
    }

    if (params->nbf)
    {
        snprintf(iatnbfexp + 21, 21, "%"PRIu64"", (uint64_t)params->nbf);
    }

    if (params->exp)
    {
        snprintf(iatnbfexp + 42, 21, "%"PRIu64"", (uint64_t)params->exp);
    }

    struct l8w8jwt_claim claims[] =
    {
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

#ifdef __cplusplus
} // extern "C"
#endif
