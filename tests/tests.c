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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>

#include "testkeys.h"
#include "l8w8jwt/base64.h"
#include "l8w8jwt/encode.h"
#include "l8w8jwt/decode.h"

#include <acutest.h>
#include <chillbuff.h>

/* Use system time if L8W8JWT_PLATFORM_TIME_ALT is set for tests*/
#if L8W8JWT_PLATFORM_TIME_ALT
l8w8jwt_time_t (*l8w8jwt_time)( l8w8jwt_time_t* time ) = time;
#endif 

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_ASSERT(true);
}

static void version_number_functions_test_success()
{
    TEST_ASSERT(l8w8jwt_get_version_number() == L8W8JWT_VERSION);

    char version_nr_str[32] = { 0x00 };
    l8w8jwt_get_version_string(version_nr_str);

    TEST_ASSERT(strcmp(L8W8JWT_VERSION_STR, version_nr_str) == 0);
}

static void test_l8w8jwt_validate_encoding_params()
{
    int r;
    char* out;
    size_t out_length;
    struct l8w8jwt_encoding_params params;

    struct l8w8jwt_claim header_claims[] = { { .key = "kid",
            .key_length = 3,
            .value = "some-key-id-here-012345",
            .value_length = 0, /* Setting this to 0 makes it use strlen(), which in this case is fine. */
            .type = L8W8JWT_CLAIM_TYPE_STRING } };

    struct l8w8jwt_claim payload_claims[] = { { .key = "tst", .key_length = 3, .value = "some-test-claim-here-012345", .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_STRING } };

    r = l8w8jwt_validate_encoding_params(NULL);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.out = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.out_length = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = L8W8JWT_MAX_KEY_SIZE + 1;
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    params.additional_header_claims = header_claims;
    params.additional_header_claims_count = 0;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    params.additional_payload_claims = payload_claims;
    params.additional_payload_claims_count = 0;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = strlen(params.secret_key);
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_validate_decoding_params()
{
    int r;
    struct l8w8jwt_decoding_params params;

    r = l8w8jwt_validate_decoding_params(NULL);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = NULL;
    r = l8w8jwt_validate_decoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.verification_key = NULL;
    r = l8w8jwt_validate_decoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = 0;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    r = l8w8jwt_validate_decoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = strlen(params.jwt);
    params.verification_key = "test key";
    params.verification_key_length = 0;
    r = l8w8jwt_validate_decoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = strlen(params.jwt);
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    r = l8w8jwt_validate_decoding_params(&params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_decoding_params_init()
{
    struct l8w8jwt_decoding_params params = { .alg = 2 };
    l8w8jwt_decoding_params_init(NULL);
    TEST_ASSERT(params.alg != -2);
    l8w8jwt_decoding_params_init(&params);
    TEST_ASSERT(params.alg == -2);
}

static void test_l8w8jwt_encoding_params_init()
{
    struct l8w8jwt_encoding_params params = { .alg = 2 };
    l8w8jwt_encoding_params_init(NULL);
    TEST_ASSERT(params.alg != -2);
    l8w8jwt_encoding_params_init(&params);
    TEST_ASSERT(params.alg == -2);
}

static void test_l8w8jwt_base64_encode_null_arg_err()
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = { 1, 2, 3, 4, 5, 6 };
    const size_t data_length = sizeof data;

    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(true, NULL, 16, &out, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(false, NULL, 16, &out, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(true, data, data_length, NULL, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(false, data, data_length, NULL, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(true, data, data_length, &out, NULL));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_encode(false, data, data_length, &out, NULL));
}

static void test_l8w8jwt_base64_encode_invalid_arg_err()
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = { 1, 2, 3, 4, 5, 6 };

    TEST_ASSERT(L8W8JWT_INVALID_ARG == l8w8jwt_base64_encode(true, data, 0, &out, &out_length));
    TEST_ASSERT(L8W8JWT_INVALID_ARG == l8w8jwt_base64_encode(false, data, 0, &out, &out_length));
}

static void test_l8w8jwt_base64_encode_overflow_err()
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = { 1, 2, 3, 4, 5, 6 };

    TEST_ASSERT(L8W8JWT_OVERFLOW == l8w8jwt_base64_encode(true, data, SIZE_MAX - 64, &out, &out_length));
    TEST_ASSERT(L8W8JWT_OVERFLOW == l8w8jwt_base64_encode(false, data, SIZE_MAX - 64, &out, &out_length));
}

static void test_l8w8jwt_base64_encode_success()
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = { 1, 2, 3, 4, 5, 6 };
    const size_t data_length = sizeof data;

    TEST_ASSERT(L8W8JWT_SUCCESS == l8w8jwt_base64_encode(true, data, data_length, &out, &out_length));
    TEST_ASSERT(L8W8JWT_SUCCESS == l8w8jwt_base64_encode(false, data, data_length, &out, &out_length));
}

static void test_l8w8jwt_base64_decode_null_arg_err()
{
    uint8_t* out;
    size_t out_length;
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_decode(true, NULL, 5, &out, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_decode(true, "12345", 5, NULL, &out_length));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_base64_decode(true, "12345", 5, &out, NULL));
}

static void test_l8w8jwt_base64_decode_success()
{
    uint8_t* out;
    size_t out_length;
    TEST_ASSERT(L8W8JWT_SUCCESS == l8w8jwt_base64_decode(0, "MTIz", strlen("MTIz"), &out, &out_length));
    TEST_ASSERT(out_length == 3);
    TEST_ASSERT(out[0] == '1');
    TEST_ASSERT(out[1] == '2');
    TEST_ASSERT(out[2] == '3');
}

static void test_l8w8jwt_encode_invalid_alg_arg_err()
{
    int r;
    char* out = NULL;
    size_t out_length = 0;
    struct l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);

    params.secret_key = "test key";
    params.secret_key_length = strlen(params.secret_key);
    params.out = &out;
    params.out_length = &out_length;
    params.iat = l8w8jwt_time(NULL);
    params.exp = l8w8jwt_time(NULL) + 600;
    params.iss = "test iss";
    params.aud = "test sub";
    params.alg = -3;

    r = l8w8jwt_encode(&params);
    TEST_ASSERT(out == NULL);
    TEST_ASSERT(out_length == 0);
    TEST_ASSERT(r != L8W8JWT_SUCCESS);
    TEST_ASSERT(r == L8W8JWT_INVALID_ARG);
}

static void test_l8w8jwt_encode_creates_nul_terminated_valid_string()
{
    int r;
    char* out;
    size_t out_length;
    struct l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);

    params.secret_key = "test key";
    params.secret_key_length = strlen(params.secret_key);
    params.out = &out;
    params.out_length = &out_length;
    params.iat = l8w8jwt_time(NULL);
    params.exp = l8w8jwt_time(NULL) + 600;
    params.iss = "test iss";
    params.aud = "test sub";
    params.alg = L8W8JWT_ALG_HS256;

    r = l8w8jwt_encode(&params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    TEST_ASSERT(out_length > 0);
    TEST_ASSERT(*out == 'e');
    TEST_ASSERT(*(out + out_length) == '\0');
    TEST_ASSERT(*(out + out_length - 1) != '\0');

    int dots = 0;
    for (char* c = out; c < out + out_length; c++)
        if (*c == '.')
            dots++;

    TEST_ASSERT(dots == 2);
    free(out);
}

static void test_l8w8jwt_decode_null_arg_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    r = l8w8jwt_decode(NULL, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params, NULL, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params, &validation_result, &claims, NULL);
    TEST_ASSERT(r == L8W8JWT_NULL_ARG);

    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_out_validation_result_null_arg_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "not a valid jwt";
    params.jwt_length = strlen(params.jwt);
    r = l8w8jwt_decode(&params, NULL, &claims, &claims_length);
    TEST_ASSERT(L8W8JWT_NULL_ARG == r);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_token_base64_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = (unsigned char*)"test key";
    params.verification_key_length = strlen((const char*)params.verification_key);
    params.jwt = "enotavalidjwt!^?.payloadisalsowrong.omfg1337shitm8";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_BASE64_FAILURE);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_missing_signature_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_DECODE_FAILED_MISSING_SIGNATURE);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_payload_base64_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidpayload.signature";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_BASE64_FAILURE);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_signature_base64_err()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_BASE64_FAILURE);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_signature_hs256()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.7eMe1dyoNm0xNvZnT5asc7wo3uj412WPFukRKFfKjdk";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_VALID);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS256;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_hs384()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS384;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.NCrZ423t7J3jlUIS7vVLpYhMiM8hN-Maj2yuRKRiuBhoEtDWX25t-j5Yh-kkNhNZ";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_VALID);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS384;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS384;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_hs512()
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS512;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.f7QsyR0cLva8oq6Wz_PEN9tI5KajMdahsYOTcdSM8ODJSkOcCg9az5lOLCwV-pGKD544c07u4V7uby-D9Bkwog";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS512;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS512;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES256_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES256_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es256k()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256K;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256K_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256K_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES256K_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES256K_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_encode_es256_es256k_wrong_curve_alg()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256K;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r != L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_encode_es256k_es256_wrong_curve_alg()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256K_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256K_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r != L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_encode_es384_wrong_curve_alg()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r != L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_encode_es512_wrong_curve_alg()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES384_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES384_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r != L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_decode_invalid_signature_es384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES384_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES384_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES384_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES384_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES512_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES512_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES512_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES512_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_eddsa()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ED25519;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ED25519_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ED25519_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ED25519;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ED25519_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ED25519_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_because_wrong_alg_type()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    int encoding_alg = L8W8JWT_ALG_HS256;
    int decoding_alg = L8W8JWT_ALG_HS384;

    for (; decoding_alg < L8W8JWT_ALG_ES512; encoding_alg = ++decoding_alg + 1)
    {
        unsigned char* key;

        switch (encoding_alg)
        {
            case L8W8JWT_ALG_ES256:
                key = (unsigned char*)ES256_PRIVATE_KEY;
                break;
            case L8W8JWT_ALG_ES384:
                key = (unsigned char*)ES384_PRIVATE_KEY;
                break;
            case L8W8JWT_ALG_ES512:
                key = (unsigned char*)ES512_PRIVATE_KEY;
                break;
            case L8W8JWT_ALG_HS256:
            case L8W8JWT_ALG_HS384:
            case L8W8JWT_ALG_HS512:
                key = (unsigned char*)"HMAC secret key 42";
                break;
            case L8W8JWT_ALG_RS256:
            case L8W8JWT_ALG_RS384:
            case L8W8JWT_ALG_RS512:
            case L8W8JWT_ALG_PS256:
            case L8W8JWT_ALG_PS384:
            case L8W8JWT_ALG_PS512:
                key = (unsigned char*)RSA_PRIVATE_KEY;
                break;
        }

        encoding_params.alg = encoding_alg;
        encoding_params.iat = l8w8jwt_time(NULL);
        encoding_params.exp = l8w8jwt_time(NULL) + 600;

        encoding_params.secret_key = key;
        encoding_params.secret_key_length = strlen(key);

        encoding_params.out = &jwt;
        encoding_params.out_length = &jwt_length;

        r = l8w8jwt_encode(&encoding_params);
        TEST_ASSERT(r == L8W8JWT_SUCCESS);

        struct l8w8jwt_decoding_params decoding_params;
        l8w8jwt_decoding_params_init(&decoding_params);

        decoding_params.alg = decoding_alg;
        decoding_params.jwt = jwt;
        decoding_params.jwt_length = jwt_length;
        decoding_params.verification_key = encoding_params.secret_key;
        decoding_params.verification_key_length = encoding_params.secret_key_length;

        enum l8w8jwt_validation_result validation_result;
        r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

        TEST_ASSERT(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
        free(jwt);
        jwt = NULL;
    }
    free(jwt);
}

// Test signature validity (decode + validation both need to succeed).

static void test_l8w8jwt_decode_valid_signature_hs256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    struct l8w8jwt_claim additional_header_claims[] = { { .key = "test", .key_length = 4, .value = "value", .value_length = 5, .type = L8W8JWT_CLAIM_TYPE_STRING } };
    struct l8w8jwt_claim additional_payload_claims[] = { { .key = "test \"bad chars that need escaping like \\ this \\ \\ one \\ omfg y \"\"", .key_length = strlen("test \"bad chars that need escaping like \\ this \\ \\ one \\ omfg y \"\""), .value = "value with hopefully \" escaped \\ backslashes \\ and double-quotes \" \" \" damn...", .value_length = strlen("value with hopefully \" escaped \\ backslashes \\ and double-quotes \" \" \" damn..."), .type = L8W8JWT_CLAIM_TYPE_STRING } };

    encoding_params.alg = L8W8JWT_ALG_HS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    encoding_params.additional_header_claims = additional_header_claims;
    encoding_params.additional_header_claims_count = 1;

    encoding_params.additional_payload_claims = additional_payload_claims;
    encoding_params.additional_payload_claims_count = 1;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_hs384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_hs512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs256_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs384_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs512_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps256_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps384_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps512_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_TEST_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_TEST_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_eddsa()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ED25519;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ED25519_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ED25519_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ED25519;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ED25519_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ED25519_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_eddsa_alt()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ED25519;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ED25519_PRIVATE_KEY_2;
    encoding_params.secret_key_length = strlen(ED25519_PRIVATE_KEY_2) + 1;

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ED25519;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ED25519_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ED25519_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es256()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES256_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES256_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es256_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_PRIME256v1_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_PRIME256v1_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_PRIME256v1_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_PRIME256v1_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es384()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES384_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES384_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES384_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES384_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es384_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_secp384r1_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_secp384r1_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_secp384r1_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_secp384r1_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es512()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES512_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES512_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES512_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES512_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es512_with_x509_certificate()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)X509_secp521r1_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(X509_secp521r1_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)X509_secp521r1_TEST_CERTIFICATE;
    decoding_params.verification_key_length = strlen(X509_secp521r1_TEST_CERTIFICATE);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

// Test claims invalidity (decode needs to succeed; validation needs to fail).

static void test_l8w8jwt_decode_invalid_exp()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL) - 300;
    encoding_params.exp = l8w8jwt_time(NULL) - 180;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_exp = true;
    decoding_params.exp_tolerance_seconds = 10;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_EXP_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_nbf()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.nbf = l8w8jwt_time(NULL) + 300;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_nbf = true;
    decoding_params.nbf_tolerance_seconds = 10;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_NBF_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_iat()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL) + 600;
    encoding_params.exp = l8w8jwt_time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iat = true;
    decoding_params.iat_tolerance_seconds = 10;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_IAT_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_sub()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.sub = "test subject";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_sub = "WRONG test subject &ç*#°§";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_SUB_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_iss()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.iss = "test issuer";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iss = "WRONG test issuer &ç*#°§";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_ISS_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_aud()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.aud = "test audience";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_aud = "WRONG test audience &ç*#°§";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_AUD_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_jti()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.jti = "test jti";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_jti = "WRONG test jti &ç*#°§";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_JTI_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_typ()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_typ = "OKP";
    decoding_params.validate_typ_length = 3;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result & L8W8JWT_TYP_FAILURE);
    free(jwt);
}

// Test claims validity (decode + validation successful).

static void test_l8w8jwt_decode_valid_exp()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_exp = true;
    decoding_params.exp_tolerance_seconds = 10;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    TEST_ASSERT(!(validation_result & L8W8JWT_EXP_FAILURE));
    free(jwt);
}

static void test_l8w8jwt_decode_valid_nbf()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.nbf = l8w8jwt_time(NULL) - 300;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_nbf = true;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    TEST_ASSERT(!(validation_result & L8W8JWT_NBF_FAILURE));
    free(jwt);
}

static void test_l8w8jwt_decode_valid_iat()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL) - 60;
    encoding_params.exp = l8w8jwt_time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iat = true;
    decoding_params.iat_tolerance_seconds = 10;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    TEST_ASSERT(!(validation_result & L8W8JWT_IAT_FAILURE));

    free(jwt);
}

static void test_l8w8jwt_decode_valid_exp_tolerance()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL) - 60;
    encoding_params.exp = l8w8jwt_time(NULL) - 30;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_exp = true;
    decoding_params.exp_tolerance_seconds = 60;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    TEST_ASSERT(!(validation_result & L8W8JWT_EXP_FAILURE));

    // Test should fail if tolerance too low.

    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_exp = true;
    decoding_params.exp_tolerance_seconds = 20;

    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
    TEST_ASSERT(validation_result & L8W8JWT_EXP_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_nbf_tolerance()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.nbf = l8w8jwt_time(NULL) + 60;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_nbf = true;
    decoding_params.nbf_tolerance_seconds = 120;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    TEST_ASSERT(!(validation_result & L8W8JWT_NBF_FAILURE));

    // Test should fail if tolerance too low.

    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_nbf = true;
    decoding_params.nbf_tolerance_seconds = 30;

    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
    TEST_ASSERT(validation_result & L8W8JWT_NBF_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_iat_tolerance()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL) + 60;
    encoding_params.exp = l8w8jwt_time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iat = true;
    decoding_params.iat_tolerance_seconds = 100;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);

    // Test should fail if tolerance too low!

    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iat = true;
    decoding_params.iat_tolerance_seconds = 30;

    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result != L8W8JWT_VALID);
    TEST_ASSERT(validation_result & L8W8JWT_IAT_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_sub()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.sub = "test subject";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_sub = "test subject";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_iss()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.iss = "test issuer";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_iss = "test issuer";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_fwd_slashes_token_decode()
{
    int r;
    char jwt[] = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkE3NHBUeDlIMDdMd1kyaGFrZVdPS0ZOZTNtaDhaNjZ3ZlFnQUhyME5OLUEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NzAxNjM4MjQsImZsaWdodF9vcGVyYXRpb25faWQiOiIzNDA4YmNlOS1kYmFiLTQ2NjUtYWJmYy04ZWEwM2IwYWQ4NzEiLCJmbGlnaHRfcGxhbl9pZCI6IjEyODE4ZTg3LTRjOTYtNGU0Yy04YzYzLTgyYjhlMTJjM2I3MyIsImlhdCI6MTY3MDE2MDIyNCwiaXNzIjoiaHR0cHM6XC9cL3Rlc3RcL2RvbWFpblwvIiwicGxhbl9maWxlX2hhc2giOiJhMmEyMDFlZmExMTFkZGU1YWFhOGY0MmI3YjQ2ZDE3YjU5NWUzOWQ4NTA1MDBkYmFjZDlmNzlhZWYwYmJmNjhlIiwic2NvcGUiOiIiLCJzdWIiOiJnMzdsWGlmQVFvQmZWdVFaeFQzVkpGalhJTWdkZlhJT3BhMkxkV0JRQGNsaWVudHMiLCJ0eXAiOiJCZWFyZXIifQ.erPylOUbAxVz03P6f5dCyjWgRA1RDUW-5pC49OGTfDEEmM9HElXx2lH5_7-C-l0HoUjypaix_s2PC9jYUUIGBsdL_2Mfary2-cxOMDyGrbfP39rD-Fq7CWrvSlqz8k9dPEEhW06Jjq2ujvcY6277Po7pXrC7PyhL3En7B3b3sUC6gk-FXVAI9XzTpxnSN5w3g7vxEi1JgI8EyfeWT1usAST8UdKYrJEzmJOvIaloq1zz1oJb9jXFGj3hCABU4Ky58ibvaiveucf5Fq8essC2jIKUBfnAy43gsj6h6kPTy5PEugSLXoomNAXthnUFckmJjY0hNwQc5yLLRa--f9ObsgFO0dKquqwGlU0BbuBZU0Dyh5-IUqNfMEG76nnr5TlzjgMusVDjCSEdDBB2ef6xdBcMiWMA-8Po2Qyd9wsKhg4ud_Hxzmutp-sEb1fhH7QcSfdeNRWnhmuGgNPaYQtx46TN8sm0IWfcVa9EUTC7IdUBAOX-o0Ob8uHjFzq97YjHawZyosj5ajgHzc8gQDIyykXO1a45r0hdMOXw7eGQ_oOC_ZWHolvNmYg38mkbpErXTUHt_Wzl3B3xuMAwMPeBskI4l_zrvmgEcGzuM1B1Igqk3pbLqJIbRBHx-VcenwevId-kGIHzfKVYmtPRO9Y6k4_njvYFYc6TcvpscmPmfGM";
    size_t jwt_length = strlen(jwt);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    struct l8w8jwt_claim claims;
    struct l8w8jwt_claim* ref = &claims;
    size_t claims_count;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, &ref, &claims_count);

    struct l8w8jwt_claim* iss_claim = l8w8jwt_get_claim(ref, claims_count, "iss", 3);
    TEST_ASSERT(strcmp(iss_claim->value, "https://test/domain/") == 0);
}

static void test_l8w8jwt_decode_valid_aud()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.aud = "test audience";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_aud = "test audience";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_jti()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.jti = "test jti";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_jti = "test jti";

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_typ()
{
    int r;
    char* jwt = NULL;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = l8w8jwt_time(NULL);
    encoding_params.exp = l8w8jwt_time(NULL) + 600;
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    TEST_ASSERT(r == L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);
    decoding_params.validate_typ = "jwt";
    decoding_params.validate_typ_length = 3;

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    TEST_ASSERT(r == L8W8JWT_SUCCESS);
    TEST_ASSERT(validation_result == L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_write_claims()
{
    struct l8w8jwt_claim claims[] = { { .key = "ctx", .key_length = 3, .value = "Unforseen Consequences", .value_length = strlen("Unforseen Consequences"), .type = L8W8JWT_CLAIM_TYPE_STRING }, { .key = "age", .key_length = 3, .value = "27", .value_length = strlen("27"), .type = L8W8JWT_CLAIM_TYPE_INTEGER }, { .key = "size", .key_length = strlen("size"), .value = "1.85", .value_length = strlen("1.85"), .type = L8W8JWT_CLAIM_TYPE_NUMBER },
        { .key = "alive", .key_length = strlen("alive"), .value = "true", .value_length = strlen("true"), .type = L8W8JWT_CLAIM_TYPE_BOOLEAN }, { .key = "nulltest", .key_length = strlen("nulltest"), .value = "null", .value_length = strlen("null"), .type = L8W8JWT_CLAIM_TYPE_NULL } };
    struct chillbuff cb;
    chillbuff_init(&cb, 16, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_write_claims(NULL, claims, 5));
    TEST_ASSERT(L8W8JWT_NULL_ARG == l8w8jwt_write_claims(&cb, NULL, 1));
    TEST_ASSERT(L8W8JWT_INVALID_ARG == l8w8jwt_write_claims(&cb, claims, 0));
    chillbuff_free(&cb);
}

static void test_l8w8jwt_get_claim()
{
    struct l8w8jwt_claim claims[] = { { .key = "ctx", .key_length = 3, .value = "Unforseen Consequences", .value_length = strlen("Unforseen Consequences"), .type = L8W8JWT_CLAIM_TYPE_STRING }, { .key = "age", .key_length = 3, .value = "27", .value_length = strlen("27"), .type = L8W8JWT_CLAIM_TYPE_INTEGER }, { .key = "size", .key_length = strlen("size"), .value = "1.85", .value_length = strlen("1.85"), .type = L8W8JWT_CLAIM_TYPE_NUMBER },
        { .key = "alive", .key_length = strlen("alive"), .value = "true", .value_length = strlen("true"), .type = L8W8JWT_CLAIM_TYPE_BOOLEAN }, { .key = "nulltest", .key_length = strlen("nulltest"), .value = "null", .value_length = strlen("null"), .type = L8W8JWT_CLAIM_TYPE_NULL } };
    TEST_ASSERT(NULL == l8w8jwt_get_claim(NULL, 5, "alive", 5));
    TEST_ASSERT(NULL == l8w8jwt_get_claim(claims, 0, "alive", 5));
    TEST_ASSERT(NULL == l8w8jwt_get_claim(claims, 5, "test", 4));
    struct l8w8jwt_claim* claim = l8w8jwt_get_claim(claims, sizeof(claims) / sizeof(struct l8w8jwt_claim), "alive", 5);
    TEST_ASSERT(strcmp(claim->key, "alive") == 0);
    TEST_ASSERT(strcmp(claim->value, "true") == 0);
}

// --------------------------------------------------------------------------------------------------------------

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    { "version_number_functions_test_success", version_number_functions_test_success }, //
    { "test_l8w8jwt_validate_encoding_params", test_l8w8jwt_validate_encoding_params }, //
    { "test_l8w8jwt_validate_decoding_params", test_l8w8jwt_validate_decoding_params }, //
    { "test_l8w8jwt_decoding_params_init", test_l8w8jwt_decoding_params_init }, //
    { "test_l8w8jwt_encoding_params_init", test_l8w8jwt_encoding_params_init }, //
    { "test_l8w8jwt_base64_encode_null_arg_err", test_l8w8jwt_base64_encode_null_arg_err }, //
    { "test_l8w8jwt_base64_encode_invalid_arg_err", test_l8w8jwt_base64_encode_invalid_arg_err }, //
    { "test_l8w8jwt_base64_encode_overflow_err", test_l8w8jwt_base64_encode_overflow_err }, //
    { "test_l8w8jwt_base64_encode_success", test_l8w8jwt_base64_encode_success }, //
    { "test_l8w8jwt_base64_decode_null_arg_err", test_l8w8jwt_base64_decode_null_arg_err }, //
    { "test_l8w8jwt_base64_decode_success", test_l8w8jwt_base64_decode_success }, //
    { "test_l8w8jwt_encode_invalid_alg_arg_err", test_l8w8jwt_encode_invalid_alg_arg_err }, //
    { "test_l8w8jwt_encode_creates_nul_terminated_valid_string", test_l8w8jwt_encode_creates_nul_terminated_valid_string }, //
    { "test_l8w8jwt_decode_null_arg_err", test_l8w8jwt_decode_null_arg_err }, //
    { "test_l8w8jwt_decode_out_validation_result_null_arg_err", test_l8w8jwt_decode_out_validation_result_null_arg_err }, //
    { "test_l8w8jwt_decode_invalid_token_base64_err", test_l8w8jwt_decode_invalid_token_base64_err }, //
    { "test_l8w8jwt_decode_missing_signature_err", test_l8w8jwt_decode_missing_signature_err }, //
    { "test_l8w8jwt_decode_invalid_payload_base64_err", test_l8w8jwt_decode_invalid_payload_base64_err }, //
    { "test_l8w8jwt_decode_invalid_signature_base64_err", test_l8w8jwt_decode_invalid_signature_base64_err }, //
    { "test_l8w8jwt_decode_invalid_signature_hs256", test_l8w8jwt_decode_invalid_signature_hs256 }, //
    { "test_l8w8jwt_decode_invalid_signature_hs384", test_l8w8jwt_decode_invalid_signature_hs384 }, //
    { "test_l8w8jwt_decode_invalid_signature_hs512", test_l8w8jwt_decode_invalid_signature_hs512 }, //
    { "test_l8w8jwt_decode_invalid_signature_rs256", test_l8w8jwt_decode_invalid_signature_rs256 }, //
    { "test_l8w8jwt_decode_invalid_signature_rs384", test_l8w8jwt_decode_invalid_signature_rs384 }, //
    { "test_l8w8jwt_decode_invalid_signature_rs512", test_l8w8jwt_decode_invalid_signature_rs512 }, //
    { "test_l8w8jwt_decode_invalid_signature_ps256", test_l8w8jwt_decode_invalid_signature_ps256 }, //
    { "test_l8w8jwt_decode_invalid_signature_ps384", test_l8w8jwt_decode_invalid_signature_ps384 }, //
    { "test_l8w8jwt_decode_invalid_signature_ps512", test_l8w8jwt_decode_invalid_signature_ps512 }, //
    { "test_l8w8jwt_decode_invalid_signature_es256", test_l8w8jwt_decode_invalid_signature_es256 }, //
    { "test_l8w8jwt_decode_invalid_signature_es256k", test_l8w8jwt_decode_invalid_signature_es256k }, //
    { "test_l8w8jwt_decode_invalid_signature_es384", test_l8w8jwt_decode_invalid_signature_es384 }, //
    { "test_l8w8jwt_decode_invalid_signature_es512", test_l8w8jwt_decode_invalid_signature_es512 }, //
    { "test_l8w8jwt_decode_fwd_slashes_token_decode", test_l8w8jwt_decode_fwd_slashes_token_decode }, //
#if L8W8JWT_ENABLE_EDDSA
    { "test_l8w8jwt_decode_invalid_signature_eddsa", test_l8w8jwt_decode_invalid_signature_eddsa }, //
#endif
    { "test_l8w8jwt_encode_es256_es256k_wrong_curve_alg", test_l8w8jwt_encode_es256_es256k_wrong_curve_alg }, //
    { "test_l8w8jwt_encode_es256k_es256_wrong_curve_alg", test_l8w8jwt_encode_es256k_es256_wrong_curve_alg }, //
    { "test_l8w8jwt_encode_es384_wrong_curve_alg", test_l8w8jwt_encode_es384_wrong_curve_alg }, //
    { "test_l8w8jwt_encode_es512_wrong_curve_alg", test_l8w8jwt_encode_es512_wrong_curve_alg }, //
    { "test_l8w8jwt_decode_invalid_signature_because_wrong_alg_type", test_l8w8jwt_decode_invalid_signature_because_wrong_alg_type }, //
    { "test_l8w8jwt_decode_invalid_exp", test_l8w8jwt_decode_invalid_exp }, //
    { "test_l8w8jwt_decode_invalid_nbf", test_l8w8jwt_decode_invalid_nbf }, //
    { "test_l8w8jwt_decode_invalid_iat", test_l8w8jwt_decode_invalid_iat }, //
    { "test_l8w8jwt_decode_invalid_sub", test_l8w8jwt_decode_invalid_sub }, //
    { "test_l8w8jwt_decode_invalid_aud", test_l8w8jwt_decode_invalid_aud }, //
    { "test_l8w8jwt_decode_invalid_iss", test_l8w8jwt_decode_invalid_iss }, //
    { "test_l8w8jwt_decode_invalid_jti", test_l8w8jwt_decode_invalid_jti }, //
    { "test_l8w8jwt_decode_invalid_typ", test_l8w8jwt_decode_invalid_typ }, //
#if L8W8JWT_ENABLE_EDDSA
    { "test_l8w8jwt_decode_valid_signature_eddsa", test_l8w8jwt_decode_valid_signature_eddsa }, //
    { "test_l8w8jwt_decode_valid_signature_eddsa_alt", test_l8w8jwt_decode_valid_signature_eddsa_alt }, //
#endif
    { "test_l8w8jwt_decode_valid_signature_hs256", test_l8w8jwt_decode_valid_signature_hs256 }, //
    { "test_l8w8jwt_decode_valid_signature_hs384", test_l8w8jwt_decode_valid_signature_hs384 }, //
    { "test_l8w8jwt_decode_valid_signature_hs512", test_l8w8jwt_decode_valid_signature_hs512 }, //
    { "test_l8w8jwt_decode_valid_signature_rs256", test_l8w8jwt_decode_valid_signature_rs256 }, //
    { "test_l8w8jwt_decode_valid_signature_rs256_with_x509_certificate", test_l8w8jwt_decode_valid_signature_rs256_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_rs384", test_l8w8jwt_decode_valid_signature_rs384 }, //
    { "test_l8w8jwt_decode_valid_signature_rs384_with_x509_certificate", test_l8w8jwt_decode_valid_signature_rs384_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_rs512", test_l8w8jwt_decode_valid_signature_rs512 }, //
    { "test_l8w8jwt_decode_valid_signature_rs512_with_x509_certificate", test_l8w8jwt_decode_valid_signature_rs512_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_ps256", test_l8w8jwt_decode_valid_signature_ps256 }, //
    { "test_l8w8jwt_decode_valid_signature_ps256_with_x509_certificate", test_l8w8jwt_decode_valid_signature_ps256_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_ps384", test_l8w8jwt_decode_valid_signature_ps384 }, //
    { "test_l8w8jwt_decode_valid_signature_ps384_with_x509_certificate", test_l8w8jwt_decode_valid_signature_ps384_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_ps512", test_l8w8jwt_decode_valid_signature_ps512 }, //
    { "test_l8w8jwt_decode_valid_signature_ps512_with_x509_certificate", test_l8w8jwt_decode_valid_signature_ps512_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_es256", test_l8w8jwt_decode_valid_signature_es256 }, //
    { "test_l8w8jwt_decode_valid_signature_es256_with_x509_certificate", test_l8w8jwt_decode_valid_signature_es256_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_es384", test_l8w8jwt_decode_valid_signature_es384 }, //
    { "test_l8w8jwt_decode_valid_signature_es384_with_x509_certificate", test_l8w8jwt_decode_valid_signature_es384_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_signature_es512", test_l8w8jwt_decode_valid_signature_es512 }, //
    { "test_l8w8jwt_decode_valid_signature_es512_with_x509_certificate", test_l8w8jwt_decode_valid_signature_es512_with_x509_certificate }, //
    { "test_l8w8jwt_decode_valid_exp", test_l8w8jwt_decode_valid_exp }, //
    { "test_l8w8jwt_decode_valid_nbf", test_l8w8jwt_decode_valid_nbf }, //
    { "test_l8w8jwt_decode_valid_iat", test_l8w8jwt_decode_valid_iat }, //
    { "test_l8w8jwt_decode_valid_exp_tolerance", test_l8w8jwt_decode_valid_exp_tolerance }, //
    { "test_l8w8jwt_decode_valid_nbf_tolerance", test_l8w8jwt_decode_valid_nbf_tolerance }, //
    { "test_l8w8jwt_decode_valid_iat_tolerance", test_l8w8jwt_decode_valid_iat_tolerance }, //
    { "test_l8w8jwt_decode_valid_sub", test_l8w8jwt_decode_valid_sub }, //
    { "test_l8w8jwt_decode_valid_aud", test_l8w8jwt_decode_valid_aud }, //
    { "test_l8w8jwt_decode_valid_iss", test_l8w8jwt_decode_valid_iss }, //
    { "test_l8w8jwt_decode_valid_jti", test_l8w8jwt_decode_valid_jti }, //
    { "test_l8w8jwt_decode_valid_exp", test_l8w8jwt_decode_valid_exp }, //
    { "test_l8w8jwt_decode_valid_nbf", test_l8w8jwt_decode_valid_nbf }, //
    { "test_l8w8jwt_decode_valid_iat", test_l8w8jwt_decode_valid_iat }, //
    { "test_l8w8jwt_decode_valid_sub", test_l8w8jwt_decode_valid_sub }, //
    { "test_l8w8jwt_decode_valid_aud", test_l8w8jwt_decode_valid_aud }, //
    { "test_l8w8jwt_decode_valid_iss", test_l8w8jwt_decode_valid_iss }, //
    { "test_l8w8jwt_decode_valid_jti", test_l8w8jwt_decode_valid_jti }, //
    { "test_l8w8jwt_decode_valid_typ", test_l8w8jwt_decode_valid_typ }, //
    { "test_l8w8jwt_write_claims", test_l8w8jwt_write_claims }, //
    { "test_l8w8jwt_get_claim", test_l8w8jwt_get_claim }, //
    //
    // ----------------------------------------------------------------------------------------------------------
    //
    { NULL, NULL } //
};