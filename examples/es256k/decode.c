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

/*
 * This keypair was generated using the following command:
 * openssl ecparam -name secp256k1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem
 */

// WARNING!
// --------
// Accidentally interchanging NIST P-256 and secp256k1 keys can happen quite quickly and is just very not good.
// Keep in mind that they only look very similar and just happen to have the same key length, but are very much different! It's a completely different curve!

static const char ECDSA_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MHQCAQEEIMRr0qJ5P1yLSjiVGVxrpSH2XHsEFbnLVG3IJ5UofWVWoAcGBSuBBAAK\n"
                                        "oUQDQgAEKDFMxQ2xpH+AabiiGGo+sXCeD52MYgufyE+AqMgsXbq9cD/TGFuqrCH3\n"
                                        "JncFWxLGamxuYQ9gdNZ9uJzk9pwgGw==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ECDSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEKDFMxQ2xpH+AabiiGGo+sXCeD52MYguf\n"
                                       "yE+AqMgsXbq9cD/TGFuqrCH3JncFWxLGamxuYQ9gdNZ9uJzk9pwgGw==\n"
                                       "-----END PUBLIC KEY-----";

static const char JWT[] = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE2MTA1NzA1MTYsImV4cCI6MTYxMDU3MTExNiwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.pb4cAxFdnow3vfMeZQiGIUH4HzS89PAAScQALucogiw9i9588Kbw90ov8-BqUyQ4uJaCf5-N14zyCCeB4haFlQ";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_ES256K;

    params.jwt = (char*)JWT;
    params.jwt_length = strlen(JWT);

    params.verification_key = (unsigned char*)ECDSA_PUBLIC_KEY;
    params.verification_key_length = strlen(ECDSA_PUBLIC_KEY);

    params.validate_iss = "Black Mesa";
    params.validate_iss_length = strlen(params.validate_iss);

    params.validate_sub = "Gordon Freeman";
    params.validate_sub_length = strlen(params.validate_sub);

    params.validate_exp = 1;
    params.exp_tolerance_seconds = 60;

    params.validate_iat = 1;
    params.iat_tolerance_seconds = 60;

    enum l8w8jwt_validation_result validation_result;
    int r = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

    printf("\nl8w8jwt_decode_es256k function returned %s (code %d).\n\nValidation result: \n%d\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, validation_result);

    return 0;
}