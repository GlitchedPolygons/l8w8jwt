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

    r = l8w8jwt_decode(NULL, &validation_result,&claims,&claims_length);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params,NULL,&claims,&claims_length);
    assert_int_equal(r, L8W8JWT_NULL_ARG);

    l8w8jwt_decoding_params_init(&params);
    r = l8w8jwt_decode(&params,&validation_result,&claims,NULL);
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
    r = l8w8jwt_decode(&params,&validation_result,&claims,&claims_length);
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
    params.verification_key = "test key";
    params.verification_key_length = strlen(params.verification_key);
    params.jwt = "enotavalidjwt!^?.payloadisalsowrong.omfg1337shitm8";
    params.jwt_length = strlen(params.jwt);

    r = l8w8jwt_decode(&params,&validation_result,&claims,&claims_length);
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
    
    r = l8w8jwt_decode(&params,&validation_result,&claims,&claims_length);
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
    
    r = l8w8jwt_decode(&params,&validation_result,&claims,&claims_length);
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
    
    r = l8w8jwt_decode(&params,&validation_result,&claims,&claims_length);
    assert_int_equal(r, L8W8JWT_BASE64_FAILURE);
    assert_int_not_equal(validation_result, L8W8JWT_VALID);
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(test_l8w8jwt_validate_encoding_params),
        cmocka_unit_test(test_l8w8jwt_validate_decoding_params),
        cmocka_unit_test(test_l8w8jwt_encode_invalid_alg_arg_err),
        cmocka_unit_test(test_l8w8jwt_encode_creates_nul_terminated_valid_string),
        cmocka_unit_test(test_l8w8jwt_decode_null_arg_err),
        cmocka_unit_test(test_l8w8jwt_decode_out_validation_result_null_arg_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_token_base64_err),
        cmocka_unit_test(test_l8w8jwt_decode_missing_signature_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_payload_base64_err),
        cmocka_unit_test(test_l8w8jwt_decode_invalid_signature_base64_err),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
