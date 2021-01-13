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
 * openssl ecparam -name secp384r1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem
 */

static const char ECDSA_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIGkAgEBBDCmT7i4o8x5NZDT2nk1D4TUxKDknyx9xGL3F0eRATDndq6MNVmkdAwl\n"
                                        "+8BaWL6xAS6gBwYFK4EEACKhZANiAASmzsk7PEHrovqP3HvWz3lRKpWM0lv//O2A\n"
                                        "wz20beljIJkKCRQiM9K4rlCcdipGwrIj/tlkBWXwbfwuLvZfkJ0SNYtUuC8H/7eu\n"
                                        "UuHfD70y0lfVQ5Ubze5luZ56j+FK+VI=\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ECDSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEps7JOzxB66L6j9x71s95USqVjNJb//zt\n"
                                       "gMM9tG3pYyCZCgkUIjPSuK5QnHYqRsKyI/7ZZAVl8G38Li72X5CdEjWLVLgvB/+3\n"
                                       "rlLh3w+9MtJX1UOVG83uZbmeeo/hSvlS\n"
                                       "-----END PUBLIC KEY-----";

static const char JWT[] = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE1ODAzNTM3MjUsImV4cCI6MTU4MDM1NDMyNSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.LQhlg6Jvj_ySDa0OIYagAZScugt3TkzlA2NAE7P2zWkg0JBE7AMAGWsoDZJui88Q1KLljylBIf0cxMBvmWC0lXDry6vnJcf6Y8MCptZpH4_10y-7e3loRuNOq1-wViiW";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_ES384;

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

    printf("\nl8w8jwt_decode_es384 function returned %s (code %d).\n\nValidation result: \n%d\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, validation_result);

    return 0;
}