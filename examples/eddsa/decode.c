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
#include "l8w8jwt/decode.h"

// See keygen.c for more infos about EdDSA key generation.

// Key generation for the other JWT algos is more straightforward and standardized (e.g. PEM-formatted RSA keys, etc...).

static const char ED25519_PRIVATE_KEY[] = "4070f09e0040304000e0f0200e1c00a058c49d1db349cbec05bf412615aad05c4675103fa2eb4d570875d58476426818cfe37b62e751b7092ee4a6606c8b7ca2";

static const char ED25519_PUBLIC_KEY[] = "4675103fa2eb4d570875d58476426818cfe37b62e751b7092ee4a6606c8b7ca2";

static const char JWT[] = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImt0eSI6IkVDIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE2MTA3MzQwMDEsImV4cCI6MTYxMDczNDYwMSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.DoXYMXT7tCt51V0QdziP7NObCSsTKc_sqZUFY14nX_uPLL4LfYorQtwi3zFNVF9act_Nz5LruvH16XIxSderCA";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_ED25519;

    params.jwt = (char*)JWT;
    params.jwt_length = strlen(JWT);

    params.verification_key = (unsigned char*)ED25519_PUBLIC_KEY;
    params.verification_key_length = strlen(ED25519_PUBLIC_KEY);

    params.validate_iss = "Black Mesa";
    params.validate_iss_length = strlen(params.validate_iss);

    params.validate_sub = "Gordon Freeman";
    params.validate_sub_length = strlen(params.validate_sub);

    params.validate_exp = 1;
    params.exp_tolerance_seconds = 60;

    params.validate_iat = 1;
    params.iat_tolerance_seconds = 60;

    params.validate_typ = "jwt";
    params.validate_typ_length = 3;

    enum l8w8jwt_validation_result validation_result;
    int r = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

    printf("\nl8w8jwt_decode_eddsa function returned %s (code %d).\n\nValidation result: \n%d\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, validation_result);

    return 0;
}