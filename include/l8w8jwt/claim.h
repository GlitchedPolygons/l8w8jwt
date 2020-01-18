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

/**
 *  @file claim.h
 *  @author Raphael Beck
 *  @brief JWT claims as described in https://auth0.com/docs/tokens/concepts/jwt-claims
 */

#ifndef L8W8JWT_CLAIM_H
#define L8W8JWT_CLAIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

/**
 * Struct containing a jwt claim key-value pair.<p>
 * If allocated on the heap by the decode function,
 * remember to call <code>l8w8jwt_claims_free()</code> on it once you're done using it.
 */
struct l8w8jwt_claim
{
    /**
     * The token claim key (e.g. "iss", "iat", "sub", etc...).<p>
     * NUL-terminated C-string!
     */
    char* key;

    /**
     * The claim's value.<p>
     * NUL-terminated C-string!
     */
    char* value;
};

/**
 * Frees a single (!) l8w8jwt_claim instance that was allocated on the heap.
 * @param claim The claims whose memory you want to reclaim. Hah.
 */
static inline void l8w8jwt_free_claim(struct l8w8jwt_claim* claim)
{
    if (claim != NULL)
    {
        free(claim->key);
        free(claim->value);
        free(claim);
    }
}

/**
 * Frees a heap-allocated array of <code>l8w8jwt_claim</code>s.
 * @param claims The claims to free.
 * @param claims_count The size of the passed claims array.
 */
static inline void l8w8jwt_free_claims(struct l8w8jwt_claim* claims, const size_t claims_count)
{
    if (claims != NULL && claims_count > 0)
    {
        for (size_t i = 0; i < claims_count; i++)
        {
            struct l8w8jwt_claim* claim = &(claims[i]);

            if (claim == NULL)
                continue;

            free(claim->key);
            free(claim->value);
        }
        free(claims);
    }
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_CLAIM_H
