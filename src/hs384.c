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

#include "l8w8jwt/hs384.h"
#include "l8w8jwt/base64.h"
#include "chillbuff.h"
#include <string.h>
#include <inttypes.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

int l8w8jwt_encode_hs384(struct l8w8jwt_encoding_params* encoding_params)
{
    int r = validate_encoding_params(encoding_params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    chillbuff stringbuilder;
    r = chillbuff_init(&stringbuilder, 512, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    r = encode(&stringbuilder, L8W8JWT_ALG_HS384, encoding_params);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    uint8_t signature_bytes[48];
    memset(signature_bytes, '\0', sizeof(signature_bytes));

    r = mbedtls_md_hmac(&mbedtls_sha384_info, encoding_params->secret_key, encoding_params->secret_key_length, (const unsigned char*)stringbuilder.array, stringbuilder.length, (unsigned char*)signature_bytes);
    if (r != 0)
    {
        chillbuff_free(&stringbuilder);
        return L8W8JWT_HS384_SIGNATURE_FAILURE;
    }

    char* signature;
    size_t signature_length;

    r = l8w8jwt_base64_encode(true, signature_bytes, sizeof(signature_bytes), &signature, &signature_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature, signature_length);

    free(signature);

    *(encoding_params->out) = malloc(stringbuilder.length + 1);
    if (*(encoding_params->out) == NULL)
    {
        chillbuff_free(&stringbuilder);
        return L8W8JWT_OUT_OF_MEM;
    }

    *(encoding_params->out_length) = stringbuilder.length;
    (*(encoding_params->out))[stringbuilder.length] = '\0';
    memcpy(*(encoding_params->out), stringbuilder.array, stringbuilder.length);

    chillbuff_free(&stringbuilder);
    return L8W8JWT_SUCCESS;
}

#ifdef __cplusplus
} // extern "C"
#endif
