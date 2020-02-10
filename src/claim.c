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

#include "l8w8jwt/claim.h"
#include "l8w8jwt/retcodes.h"

#include <string.h>
#include <mbedtls/md.h>

void l8w8jwt_free_claims(struct l8w8jwt_claim* claims, const size_t claims_count)
{
    if (claims != NULL && claims_count > 0)
    {
        for (struct l8w8jwt_claim* claim = claims; claim < claims + claims_count; claim++)
        {
            if (claim == NULL)
                continue;

            free(claim->key);
            free(claim->value);
        }
        free(claims);
    }
}

int l8w8jwt_write_claims(chillbuff* stringbuilder, struct l8w8jwt_claim* claims, const size_t claims_count)
{
    if (stringbuilder == NULL || claims == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    if (claims_count == 0)
    {
        return L8W8JWT_INVALID_ARG;
    }

    int first = 1;
    for (struct l8w8jwt_claim* claim = claims; claim < claims + claims_count; claim++)
    {
        if (claim->key == NULL)
        {
            continue;
        }

        if (!first)
        {
            chillbuff_push_back(stringbuilder, ",", 1);
        }

        chillbuff_push_back(stringbuilder, "\"", 1);
        chillbuff_push_back(stringbuilder, claim->key, claim->key_length ? claim->key_length : strlen(claim->key));
        chillbuff_push_back(stringbuilder, "\":", 2);

        if (claim->type == L8W8JWT_CLAIM_TYPE_STRING)
            chillbuff_push_back(stringbuilder, "\"", 1);

        chillbuff_push_back(stringbuilder, claim->value, claim->value_length ? claim->value_length : strlen(claim->value));

        if (claim->type == L8W8JWT_CLAIM_TYPE_STRING)
            chillbuff_push_back(stringbuilder, "\"", 1);

        first = 0;
    }

    return L8W8JWT_SUCCESS;
}

struct l8w8jwt_claim* l8w8jwt_get_claim(struct l8w8jwt_claim* claims, const size_t claims_count, const char* key, const size_t key_length)
{
    if (claims == NULL || key == NULL || claims_count == 0 || key_length == 0)
        return NULL;

    for (struct l8w8jwt_claim* claim = claims; claim < claims + claims_count; claim++)
    {
        if (strncmp(claim->key, key, key_length) == 0)
            return claim;
    }

    return NULL;
}

#ifdef __cplusplus
} // extern "C"
#endif
