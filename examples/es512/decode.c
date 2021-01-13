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
 * openssl ecparam -name secp521r1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem
 */

static const char ECDSA_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIHcAgEBBEIA99ixxKKzlE5YmWEq65ZNt6JNXbYkj1x5RrePENwo7oyBNh6v1bHL\n"
                                        "maMyT+dIGVxKXN09x7WeipdArELA891BGeWgBwYFK4EEACOhgYkDgYYABAA3XwC+\n"
                                        "Vf5yIWfKmAdUPkKOpjlklo3pijqsy7r6wnwaUQszopgv5sNxFXNt647L8lZU1KFh\n"
                                        "xFwn2GyXaoEOebcMVgGUhRURpcADMIyVgKEoZcKwjydKDNy40XLKbb4Gzv3LAwpY\n"
                                        "Os+OHwhkHmNGJ9mHIlKzpIaLSiNXwGa1ZosgwPlI6A==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ECDSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAN18AvlX+ciFnypgHVD5CjqY5ZJaN\n"
                                       "6Yo6rMu6+sJ8GlELM6KYL+bDcRVzbeuOy/JWVNShYcRcJ9hsl2qBDnm3DFYBlIUV\n"
                                       "EaXAAzCMlYChKGXCsI8nSgzcuNFyym2+Bs79ywMKWDrPjh8IZB5jRifZhyJSs6SG\n"
                                       "i0ojV8BmtWaLIMD5SOg=\n"
                                       "-----END PUBLIC KEY-----";

static const char JWT[] = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InNvbWUta2V5LWlkLWhlcmUtMDEyMzQ1In0.eyJpYXQiOjE1ODAzNTM3MjUsImV4cCI6MTU4MDM1NDMyNSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciIsImN0eCI6IlVuZm9yc2VlbiBDb25zZXF1ZW5jZXMiLCJhZ2UiOjI3LCJzaXplIjoxLjg1LCJhbGl2ZSI6dHJ1ZSwibnVsbHRlc3QiOm51bGx9.ARZYWY6qwqeF5F6eBgU3X5JAvASkSsXsBSMUixmE79Q4iXH97I0P4IUwV6DbTDnMirOchXSLZBDm4HA2M4qA5DGCAUa8YeQMgXH6CqmgF5xuzP0Sfb2unoCRUcDjeapvvNMkwhEFottGONiNNHofxFl0tRB9wz2hwD09mc-0z4FPwUKP";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_ES512;

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

    printf("\nl8w8jwt_decode_es512 function returned %s (code %d).\n\nValidation result: \n%d\n", r == L8W8JWT_SUCCESS ? "successfully" : "", r, validation_result);

    return 0;
}