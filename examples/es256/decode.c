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
 * openssl ecparam -name prime256v1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem
 */

static const char ECDSA_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49\n"
                                        "AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB\n"
                                        "5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ECDSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk\n"
                                       "NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                       "-----END PUBLIC KEY-----";

static const char JWT[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE1ODAzNTM3MjUsImV4cCI6MTU4MDM1NDMyNSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.piI9-ViSixpwMS-hA8jOpoaLL7i9Lat66eSC-GqH22k2p_xbY6-ZMLF36OtqapaITGBKSnGWI1cPcYhOrP3IJQ";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_ES256;

    params.jwt = (char*)JWT;
    params.jwt_length = strlen(JWT);

    params.verification_key = (unsigned char*)ECDSA_PUBLIC_KEY;
    params.verification_key_length = strlen(ECDSA_PUBLIC_KEY);

    params.validate_iss = "Black Mesa";
    params.validate_iss_length = strlen(params.validate_iss);

    params.validate_sub = "Gordon Freeman";
    params.validate_sub_length = strlen(params.validate_sub);

    params.validate_exp = true;
    params.exp_tolerance_seconds = 60;

    params.validate_iat = true;
    params.iat_tolerance_seconds = 60;

    enum l8w8jwt_validation_result validation_result;
    int r = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

    printf("\nl8w8jwt_decode_es256 function returned %s (code %d).\n\nValidation result: \n%d\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, validation_result);

    return 0;
}