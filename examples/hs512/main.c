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

#include <stdio.h>
#include <string.h>
#include "l8w8jwt/hs512.h"

int main(void)
{
    char* jwt;
    size_t jwt_length;

    struct l8w8jwt_claim header_claims[] =
    {
        {
            .key = "kid",
            .key_length = 3,
            .value = "some-key-id-here-012345",
            .value_length = strlen("some-key-id-here-012345"),
            .type = L8W8JWT_CLAIM_TYPE_STRING
        }
    };

    struct l8w8jwt_claim payload_claims[] =
    {
        {
            .key = "ctx",
            .key_length = 3,
            .value = "Unforseen Consequences",
            .value_length = strlen("Unforseen Consequences"),
            .type = L8W8JWT_CLAIM_TYPE_STRING
        },
        {
            .key = "age",
            .key_length = 3,
            .value = "27",
            .value_length = strlen("27"),
            .type = L8W8JWT_CLAIM_TYPE_INTEGER
        },
        {
            .key = "size",
            .key_length = strlen("size"),
            .value = "1.85",
            .value_length = strlen("1.85"),
            .type = L8W8JWT_CLAIM_TYPE_NUMBER
        },
        {
            .key = "alive",
            .key_length = strlen("alive"),
            .value = "true",
            .value_length = strlen("true"),
            .type = L8W8JWT_CLAIM_TYPE_BOOLEAN
        },
        {
            .key = "nulltest",
            .key_length = strlen("nulltest"),
            .value = "null",
            .value_length = strlen("null"),
            .type = L8W8JWT_CLAIM_TYPE_NULL
        }
    };

    struct l8w8jwt_encoding_params params =
    {
        .sub = "Gordon Freeman",
        .sub_length = strlen("Gordon Freeman"),

        .iss = "Black Mesa",
        .iss_length = strlen("Black Mesa"),

        .aud = "Administrator",
        .aud_length = strlen("Administrator"),

        .iat = time(NULL),
        .exp = time(NULL) + 600,

        .additional_header_claims = header_claims,
        .additional_header_claims_count = sizeof(header_claims) / sizeof(struct l8w8jwt_claim),

        .additional_payload_claims = payload_claims,
        .additional_payload_claims_count = sizeof(payload_claims) / sizeof(struct l8w8jwt_claim),

        .secret_key = (unsigned char*)"test key",
        .secret_key_length = strlen("test key"),

        .out = &jwt,
        .out_length = &jwt_length
    };

    int r = l8w8jwt_encode_hs512(&params);
    printf("\nl8w8jwt_encode_hs512 function returned %s (code %d).\n\nCreated token: \n%s\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, jwt);

    free(jwt);
    return r;
}