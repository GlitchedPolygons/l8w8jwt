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
#include <cmocka.h>
#include "testkeys.h"
#include "l8w8jwt/base64.h"
#include "l8w8jwt/encode.h"
#include "l8w8jwt/decode.h"

/* A test case that does nothing and succeeds. */
static void null_test_success(void** state)
{
    (void)state;
}

static void test_l8w8jwt_validate_encoding_params(void** state)
{
    int r;
    char* out;
    size_t out_length;
    struct l8w8jwt_encoding_params params;

    struct l8w8jwt_claim header_claims[] =
    {
        {
            .key = "kid",
            .key_length = 3,
            .value = "some-key-id-here-012345",
            .value_length = 0, /* Setting this to 0 makes it use strlen(), which in this case is fine. */
            .type = L8W8JWT_CLAIM_TYPE_STRING
        }
    };

    struct l8w8jwt_claim payload_claims[] =
    {
        {
            .key = "tst",
            .key_length = 3,
            .value = "some-test-claim-here-012345",
            .value_length = 0,
            .type = L8W8JWT_CLAIM_TYPE_STRING
        }
    };

    r = l8w8jwt_validate_encoding_params(NULL);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.out = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.out_length = NULL;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = L8W8JWT_MAX_KEY_SIZE + 1;
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    params.additional_header_claims = header_claims;
    params.additional_header_claims_count = 0;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = 0;
    params.out = &out;
    params.out_length = &out_length;
    params.additional_payload_claims = payload_claims;
    params.additional_payload_claims_count = 0;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_encoding_params_init(&params);
    params.secret_key = "test key";
    params.secret_key_length = strlen(params.secret_key);
    params.out = &out;
    params.out_length = &out_length;
    r = l8w8jwt_validate_encoding_params(&params);
    assert_int_equal(r, L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_validate_decoding_params(void** state)
{
    int r;
    struct l8w8jwt_decoding_params params;

    r = l8w8jwt_validate_decoding_params(NULL);
    assert_int_equal(r, L8W8JWT_NULL_ARG);
    
    l8w8jwt_decoding_params_init(&params);
    params.jwt = NULL;
    r = l8w8jwt_validate_decoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.verification_key = NULL;
    r = l8w8jwt_validate_decoding_params(&params);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = 0;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    r = l8w8jwt_validate_decoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = strlen(params.jwt);
    params.verification_key = "test key";
    params.verification_key_length = 0;
    r = l8w8jwt_validate_decoding_params(&params);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);

    l8w8jwt_decoding_params_init(&params);
    params.jwt = "test jwt";
    params.jwt_length = strlen(params.jwt);
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    r = l8w8jwt_validate_decoding_params(&params);
    assert_int_equal(r, L8W8JWT_SUCCESS);
}

static void test_l8w8jwt_decoding_params_init(void** state)
{
    struct l8w8jwt_decoding_params params = {.alg = 2};
    l8w8jwt_decoding_params_init(NULL);
    assert_int_not_equal(params.alg, -2);
    l8w8jwt_decoding_params_init(&params);
    assert_int_equal(params.alg, -2);
}

static void test_l8w8jwt_encoding_params_init(void** state)
{
    struct l8w8jwt_encoding_params params = {.alg = 2};
    l8w8jwt_encoding_params_init(NULL);
    assert_int_not_equal(params.alg, -2);
    l8w8jwt_encoding_params_init(&params);
    assert_int_equal(params.alg, -2);
}

static void test_l8w8jwt_base64_encode_null_arg_err(void** state)
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = {1,2,3,4,5,6};
    const size_t data_length = sizeof data;

    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(true, NULL, 16, &out, &out_length));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(false, NULL, 16, &out, &out_length));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(true, data, data_length, NULL, &out_length));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(false, data, data_length, NULL, &out_length));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(true, data, data_length, &out, NULL));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_base64_encode(false, data, data_length, &out, NULL));
}

static void test_l8w8jwt_base64_encode_invalid_arg_err(void** state)
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = {1,2,3,4,5,6};

    assert_int_equal(L8W8JWT_INVALID_ARG, l8w8jwt_base64_encode(true, data, 0, &out, &out_length));
    assert_int_equal(L8W8JWT_INVALID_ARG, l8w8jwt_base64_encode(false, data, 0, &out, &out_length));
}

static void test_l8w8jwt_base64_encode_overflow_err(void** state)
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = {1,2,3,4,5,6};

    assert_int_equal(L8W8JWT_OVERFLOW, l8w8jwt_base64_encode(true, data, SIZE_MAX - 64, &out, &out_length));
    assert_int_equal(L8W8JWT_OVERFLOW, l8w8jwt_base64_encode(false, data, SIZE_MAX - 64, &out, &out_length));
}

static void test_l8w8jwt_base64_encode_success(void** state)
{
    char* out = NULL;
    size_t out_length = 0;
    unsigned char data[] = {1,2,3,4,5,6};
    const size_t data_length = sizeof data;

    assert_int_equal(L8W8JWT_SUCCESS, l8w8jwt_base64_encode(true, data, data_length, &out, &out_length));
    assert_int_equal(L8W8JWT_SUCCESS, l8w8jwt_base64_encode(false, data, data_length, &out, &out_length));
}

static void test_l8w8jwt_encode_invalid_alg_arg_err(void** state)
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
    params.iat = time(NULL);
    params.exp = time(NULL) + 600;
    params.iss = "test iss";
    params.aud = "test sub";
    params.alg = -3;
    
    r = l8w8jwt_encode(&params);
    assert_null(out);
    assert_int_equal(out_length, 0);
    assert_int_not_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(r, L8W8JWT_INVALID_ARG);
}

static void test_l8w8jwt_encode_creates_nul_terminated_valid_string(void** state)
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
    params.iat = time(NULL);
    params.exp = time(NULL) + 600;
    params.iss = "test iss";
    params.aud = "test sub";
    params.alg = L8W8JWT_ALG_HS256;

    r = l8w8jwt_encode(&params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    assert_true(out_length > 0);
    assert_int_equal(*out, 'e');
    assert_true(*(out + out_length) == '\0');
    assert_true(*(out + out_length - 1) != '\0');

    int dots = 0;
    for(char* c = out; c < out + out_length; c++)
      if(*c == '.')
        dots++;

    assert_int_equal(dots, 2);
    free(out);
}

static void test_l8w8jwt_decode_null_arg_err(void** state)
{
    int r;
    size_t claims_length;
    struct l8w8jwt_claim* claims;
    struct l8w8jwt_decoding_params params;
    enum l8w8jwt_validation_result validation_result = -1;

    r = l8w8jwt_decode(NULL, &validation_result, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params, NULL, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params, &validation_result, &claims, NULL);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_out_validation_result_null_arg_err(void** state)
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
    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_token_base64_err(void** state)
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
    assert_int_equal(r, L8W8JWT_BASE64_FAILURE);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_missing_signature_err(void** state)
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
    assert_int_equal(r, L8W8JWT_DECODE_FAILED_MISSING_SIGNATURE);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_payload_base64_err(void** state)
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
    assert_int_equal(r, L8W8JWT_BASE64_FAILURE);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_signature_base64_err(void** state)
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
    assert_int_equal(r, L8W8JWT_BASE64_FAILURE);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

static void test_l8w8jwt_decode_invalid_signature_hs256(void** state)
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
    assert_int_equal(r, L8W8JWT_VALID);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS256;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS256;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_hs384(void** state)
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
    assert_int_equal(r, L8W8JWT_VALID);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS384;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS384;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_hs512(void** state)
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
    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS512;
    encoding_params.sub = "Gordon Freeman";
    encoding_params.iss = "Black Mesa";
    encoding_params.aud = "Administrator";
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */
    encoding_params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    l8w8jwt_decoding_params_init(&params);
    params.alg = L8W8JWT_ALG_HS512;
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = jwt;
    params.jwt_length = jwt_length;

    r = l8w8jwt_decode(&params, &validation_result, &claims, &claims_length);
    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_rs512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_ps512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES256_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES256_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES384_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES384_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES384_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES384_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_es512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES512_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES512_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES512_PUBLIC_KEY_2;
    decoding_params.verification_key_length = strlen(ES512_PUBLIC_KEY_2);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_signature_because_wrong_alg_type(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    int encoding_alg = L8W8JWT_ALG_HS256;
    int decoding_alg = L8W8JWT_ALG_HS384;

    for(; decoding_alg < L8W8JWT_ALG_ES512; encoding_alg = ++decoding_alg + 1)
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
        encoding_params.iat = time(NULL);
        encoding_params.exp = time(NULL) + 600;
    
        encoding_params.secret_key = key;
        encoding_params.secret_key_length = strlen(key);
    
        encoding_params.out = &jwt;
        encoding_params.out_length = &jwt_length;
    
        r = l8w8jwt_encode(&encoding_params);
        assert_int_equal(r, L8W8JWT_SUCCESS);
    
        struct l8w8jwt_decoding_params decoding_params;
        l8w8jwt_decoding_params_init(&decoding_params);
    
        decoding_params.alg = decoding_alg;
        decoding_params.jwt = jwt;
        decoding_params.jwt_length = jwt_length;
        decoding_params.verification_key = encoding_params.secret_key;
        decoding_params.verification_key_length = encoding_params.secret_key_length;
    
        enum l8w8jwt_validation_result validation_result;
        r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);
    
        assert_true(validation_result & L8W8JWT_SIGNATURE_VERIFICATION_FAILURE);
        free(jwt);
        jwt = NULL;
    }
    free(jwt);
}

// Test signature validity (decode + validation both need to succeed).

static void test_l8w8jwt_decode_valid_signature_hs256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_hs384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_hs512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_HS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)"the cake is a lie";
    encoding_params.secret_key_length = strlen(encoding_params.secret_key);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_HS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)"the cake is a lie";
    decoding_params.verification_key_length = strlen(decoding_params.verification_key);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_rs512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_RS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_RS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_ps512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_PS512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)RSA_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(RSA_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es256(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES256;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES256_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES256_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES256;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES256_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES256_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es384(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES384;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES384_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES384_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES384;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES384_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES384_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_signature_es512(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_ES512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600; // Set to expire after 10 minutes (600 seconds).

    encoding_params.secret_key = (unsigned char*)ES512_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(ES512_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

    struct l8w8jwt_decoding_params decoding_params;
    l8w8jwt_decoding_params_init(&decoding_params);

    decoding_params.alg = L8W8JWT_ALG_ES512;
    decoding_params.jwt = jwt;
    decoding_params.jwt_length = jwt_length;
    decoding_params.verification_key = (unsigned char*)ES512_PUBLIC_KEY;
    decoding_params.verification_key_length = strlen(ES512_PUBLIC_KEY);

    enum l8w8jwt_validation_result validation_result;
    r = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

// Test claims invalidity (decode needs to succeed; validation needs to fail).

static void test_l8w8jwt_decode_invalid_exp(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL) - 300;
    encoding_params.exp = time(NULL) - 180;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_EXP_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_nbf(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.nbf = time(NULL) + 300;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_NBF_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_iat(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL) + 600;
    encoding_params.exp = time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_IAT_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_sub(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.sub = "test subject";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_SUB_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_iss(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.iss = "test issuer";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_ISS_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_aud(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.aud = "test audience";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_AUD_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_invalid_jti(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.jti = "test jti";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_true(validation_result & L8W8JWT_JTI_FAILURE);
    free(jwt);
}

// Test claims validity (decode + validation successful).

static void test_l8w8jwt_decode_valid_exp(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    assert_false(validation_result & L8W8JWT_EXP_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_nbf(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.nbf = time(NULL) - 300;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    assert_false(validation_result & L8W8JWT_NBF_FAILURE);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_iat(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL) - 60;
    encoding_params.exp = time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    assert_false(validation_result & L8W8JWT_IAT_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_exp_tolerance(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL) - 60;
    encoding_params.exp = time(NULL) - 30;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    assert_false(validation_result & L8W8JWT_EXP_FAILURE);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
    assert_true(validation_result & L8W8JWT_EXP_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_nbf_tolerance(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.nbf = time(NULL) + 60;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    assert_false(validation_result & L8W8JWT_NBF_FAILURE);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
    assert_true(validation_result & L8W8JWT_NBF_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_iat_tolerance(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL) + 60;
    encoding_params.exp = time(NULL) + 900;

    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
    assert_true(validation_result & L8W8JWT_IAT_FAILURE);

    free(jwt);
}

static void test_l8w8jwt_decode_valid_sub(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.sub = "test subject";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_iss(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.iss = "test issuer";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_aud(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.aud = "test audience";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_decode_valid_jti(void** state)
{
    int r;
    char* jwt;
    size_t jwt_length;
    struct l8w8jwt_encoding_params encoding_params;
    l8w8jwt_encoding_params_init(&encoding_params);

    encoding_params.alg = L8W8JWT_ALG_PS512;
    encoding_params.iat = time(NULL);
    encoding_params.exp = time(NULL) + 600;
    encoding_params.jti = "test jti";
    encoding_params.secret_key = (unsigned char*)RSA_PRIVATE_KEY;
    encoding_params.secret_key_length = strlen(RSA_PRIVATE_KEY);

    encoding_params.out = &jwt;
    encoding_params.out_length = &jwt_length;

    r = l8w8jwt_encode(&encoding_params);
    assert_int_equal(r, L8W8JWT_SUCCESS);

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

    assert_int_equal(r, L8W8JWT_SUCCESS);
    assert_int_equal(validation_result, L8W8JWT_VALID);
    free(jwt);
}

static void test_l8w8jwt_write_claims(void** state)
{
    chillbuff cb;
    chillbuff_init(&cb,16, sizeof(char),CHILLBUFF_GROW_DUPLICATIVE);
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_write_claims(NULL, 1, 1));
    assert_int_equal(L8W8JWT_NULL_ARG, l8w8jwt_write_claims(&cb, NULL, 1));
    assert_int_equal(L8W8JWT_INVALID_ARG, l8w8jwt_write_claims(&cb, 1, 0));
    chillbuff_free(&cb);
}

static void test_l8w8jwt_get_claim(void** state)
{
    const struct l8w8jwt_claim claims[] =
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
    assert_null(l8w8jwt_get_claim(NULL, 5, "alive", 5));
    assert_null(l8w8jwt_get_claim(claims, 0, "alive", 5));
    assert_null(l8w8jwt_get_claim(claims, 5, "test", 4));
    struct l8w8jwt_claim* claim = l8w8jwt_get_claim(claims, sizeof(claims) / sizeof(struct l8w8jwt_claim), "alive", 5);
    assert_string_equal(claim->key, "alive");
    assert_string_equal(claim->value, "true");
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(test_l8w8jwt_validate_encoding_params),
        cmocka_unit_test(test_l8w8jwt_validate_decoding_params),
        cmocka_unit_test(test_l8w8jwt_decoding_params_init),
        cmocka_unit_test(test_l8w8jwt_encoding_params_init),
        cmocka_unit_test(test_l8w8jwt_base64_encode_null_arg_err),
        cmocka_unit_test(test_l8w8jwt_base64_encode_invalid_arg_err),
        cmocka_unit_test(test_l8w8jwt_base64_encode_overflow_err),
        cmocka_unit_test(test_l8w8jwt_base64_encode_success),
        cmocka_unit_test(test_l8w8jwt_encode_invalid_alg_arg_err),
        cmocka_unit_test(test_l8w8jwt_encode_creates_nul_terminated_valid_string),
        cmocka_unit_test(test_l8w8jwt_decode_null_arg_err),
        cmocka_unit_test(test_l8w8jwt_decode_out_validation_result_null_arg_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_token_base64_err),
        cmocka_unit_test(test_l8w8jwt_decode_missing_signature_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_payload_base64_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_base64_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_hs256),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_hs384),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_hs512),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_rs256),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_rs384),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_rs512),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_ps256),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_ps384),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_ps512),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_es256),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_es384),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_es512),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_because_wrong_alg_type),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_exp),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_nbf),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_iat),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_sub),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_aud),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_iss),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_jti),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_hs256),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_hs384),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_hs512),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_rs256),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_rs384),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_rs512),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_ps256),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_ps384),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_ps512),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_es256),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_es384),
        cmocka_unit_test(test_l8w8jwt_decode_valid_signature_es512),
        cmocka_unit_test(test_l8w8jwt_decode_valid_exp),
        cmocka_unit_test(test_l8w8jwt_decode_valid_nbf),
        cmocka_unit_test(test_l8w8jwt_decode_valid_iat),
        cmocka_unit_test(test_l8w8jwt_decode_valid_exp_tolerance),
        cmocka_unit_test(test_l8w8jwt_decode_valid_nbf_tolerance),
        cmocka_unit_test(test_l8w8jwt_decode_valid_iat_tolerance),
        cmocka_unit_test(test_l8w8jwt_decode_valid_sub),
        cmocka_unit_test(test_l8w8jwt_decode_valid_aud),
        cmocka_unit_test(test_l8w8jwt_decode_valid_iss),
        cmocka_unit_test(test_l8w8jwt_decode_valid_jti),
        cmocka_unit_test(test_l8w8jwt_decode_valid_exp),
        cmocka_unit_test(test_l8w8jwt_decode_valid_nbf),
        cmocka_unit_test(test_l8w8jwt_decode_valid_iat),
        cmocka_unit_test(test_l8w8jwt_decode_valid_sub),
        cmocka_unit_test(test_l8w8jwt_decode_valid_aud),
        cmocka_unit_test(test_l8w8jwt_decode_valid_iss),
        cmocka_unit_test(test_l8w8jwt_decode_valid_jti),
        cmocka_unit_test(test_l8w8jwt_write_claims),
        cmocka_unit_test(test_l8w8jwt_get_claim),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
