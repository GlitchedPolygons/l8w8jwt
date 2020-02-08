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

static const char ES256_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49\n"
                                        "AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB\n"
                                        "5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES256_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk\n"
                                       "NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                       "-----END PUBLIC KEY-----";

static const char ES384_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIGkAgEBBDCmT7i4o8x5NZDT2nk1D4TUxKDknyx9xGL3F0eRATDndq6MNVmkdAwl\n"
                                        "+8BaWL6xAS6gBwYFK4EEACKhZANiAASmzsk7PEHrovqP3HvWz3lRKpWM0lv//O2A\n"
                                        "wz20beljIJkKCRQiM9K4rlCcdipGwrIj/tlkBWXwbfwuLvZfkJ0SNYtUuC8H/7eu\n"
                                        "UuHfD70y0lfVQ5Ubze5luZ56j+FK+VI=\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES384_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEps7JOzxB66L6j9x71s95USqVjNJb//zt\n"
                                       "gMM9tG3pYyCZCgkUIjPSuK5QnHYqRsKyI/7ZZAVl8G38Li72X5CdEjWLVLgvB/+3\n"
                                       "rlLh3w+9MtJX1UOVG83uZbmeeo/hSvlS\n"
                                       "-----END PUBLIC KEY-----";

static const char ES512_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIHcAgEBBEIA99ixxKKzlE5YmWEq65ZNt6JNXbYkj1x5RrePENwo7oyBNh6v1bHL\n"
                                        "maMyT+dIGVxKXN09x7WeipdArELA891BGeWgBwYFK4EEACOhgYkDgYYABAA3XwC+\n"
                                        "Vf5yIWfKmAdUPkKOpjlklo3pijqsy7r6wnwaUQszopgv5sNxFXNt647L8lZU1KFh\n"
                                        "xFwn2GyXaoEOebcMVgGUhRURpcADMIyVgKEoZcKwjydKDNy40XLKbb4Gzv3LAwpY\n"
                                        "Os+OHwhkHmNGJ9mHIlKzpIaLSiNXwGa1ZosgwPlI6A==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES512_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAN18AvlX+ciFnypgHVD5CjqY5ZJaN\n"
                                       "6Yo6rMu6+sJ8GlELM6KYL+bDcRVzbeuOy/JWVNShYcRcJ9hsl2qBDnm3DFYBlIUV\n"
                                       "EaXAAzCMlYChKGXCsI8nSgzcuNFyym2+Bs79ywMKWDrPjh8IZB5jRifZhyJSs6SG\n"
                                       "i0ojV8BmtWaLIMD5SOg=\n"
                                       "-----END PUBLIC KEY-----";

static const char RSA_PRIVATE_KEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                                      "MIIJJwIBAAKCAgEAoWFe7BbX1nWo5oaSv/JvIUCWsk/Vi2q8P0cGkefgN5J7MN7K\n"
                                      "fv7lq0hl/1cZcJs81IC+GiC+V3aR2zLBNnJJaxa4sqk+hF5DJcD2bF0B80uqPYQU\n"
                                      "XlQwki/heATnVcke8APuY0kOZykxoD0APAqw0z5KDqgt2vA9G6keM6b9bbL+IvxM\n"
                                      "+yMk1QV0OQLh6Rkz46DyPSoUFWyXiist47PJKNyZAfFZx6vEivzBmqRHKe11W9oD\n"
                                      "/tN5VTQCH/UTSRfyWq/UUMFVMCksLwT6XoWI7F5swgQkSahWkVJ93Qf8cUf1HIZY\n"
                                      "TMJBYPG4y2NDZ0+ytnH3BNXLMQXg9xbgv6B/iaSVScI4CWIpQTAtNKnJwYg2+Rhf\n"
                                      "YBC07iM56c4a+TjbCWgmd11UYc96dbw83uFRjKZc3+SC38ITCgMuoDPNBlFJK6u8\n"
                                      "VfYylGEJolGcauVa6yZKwzsJGr5J/LANz+ZyHZmANed+2Hjqxu/H1NGDBdvUGLQb\n"
                                      "hb/uBJ8oG8iAW5eUyjEJMX0RuncYnBrUjZdEFr0zJd5VkrfFTd26AjGusbiBevAT\n"
                                      "fj83SNa9uK3N3lSNcLNyNXUjmfOU21NWHAk5QV3TJb6SCTcqWFaYoyKR7H6zxRcA\n"
                                      "rNuIAMW4KhOl4jdNnTxJllC4tr/gkE+uO1ntB9ymLxQBRp8osHjuZpKXr3cCAwEA\n"
                                      "AQKCAgAXtQGoRgzMDPnUb6WEPB2WMXJR3Id+1R21X/43lewqzcJ6Ieh2coSTvm15\n"
                                      "bramg6+Seh0zImdD2v+/Rzv5/x0I9cwJNvKfqGdN1wR8U8dzEcT/B3Wki9Kczxrc\n"
                                      "sj+3qvV4BePRwwwyHGuVYhC0QU/LoIVplMwzswIPG697oAbvxBEwW4cFh5qkDoqN\n"
                                      "y34ba5/jSyP610EfCpZSblht8F3XOlzh2644NmQHlOzuBj8MCj2o0iSvHSrgWOUN\n"
                                      "A8gi/zkTmGvktxoIGqxKdf0/wHcmXhK1B7268ldRPuCNhVxQ2eTInXXARPMsxiXC\n"
                                      "/yCKPzt+MMy8cZnJaFcthTdb/zxs5CKKgBKIl5svSW3ZO27SXJ8jo8m0cUUxwAQO\n"
                                      "jJCNroBMBlCDN/sILhpzgnPLkVXnK+/uUYSBe/oOHd7mL38ohlMPepbCeFu4r6fP\n"
                                      "xpOrROTIzDblg9/cne/TLqSPu2K6qbsXFoL3v95V9ieAETnGkTHuKwqW1gMYtOin\n"
                                      "Ad0GWIl4PZCAjbKptSFTM5/8nWiPdJ3YnkE0nQDSgK66ZRjyRCVSzE5CcgbiVlMW\n"
                                      "mXVsIXnt/RHsLsPuGuzURhSmjVg+x0g2nAPmnZuG+7wJOF1vVCYT1gufblaHEBAo\n"
                                      "ofcmYfdYxhd2iQmWJi/uwnC0f6YdF+wq+fLFuPMPgCMvdhe/oQKCAQEA6p8BV4qA\n"
                                      "aRbcV137k4/+jx3zrOA736kRjmHatR1fq0MDTk4JfvWrH5kfl8VS6b4fiYsDVTx6\n"
                                      "ylxYV1paqRUfNmfzuPQStM+arkFIw/6754CoESvqF/uU/JRe6WZIB1Jr3A4XNzZe\n"
                                      "p/9+0hJeQlwRUWPhWMUNIJPjaQ3kmdeIUEsRcIkf4e4xJzhilnxarK4/nkqicgo6\n"
                                      "H2JRD1QKtO96ncGDDLmwWXMxYA9RUHaURYten9bi36V8gt69/zI6B8uTyMJttUma\n"
                                      "ziMr4nBsvfJDT0C0LG9SqsAfPkUMWyHSXxXn7N7S4Yy48k+wyp6FMKN13d/aWqdy\n"
                                      "K4n2W8ux8sHMIQKCAQEAsBXh0HO8eZpanq3Vl0tiHmCpjTsXFUg/hOGrck4s/vaG\n"
                                      "mLiSqCHKX6qfoLrEWUiPfCuqBprAsSebq2c/xkWdwW1UP/6m6dh6REXHbZbTyot4\n"
                                      "JNSPwNSvfu3P6cmLFyao4u6AciO/V18kGXf64XsDZ9gb47oVGtcSmYcsHsVTIyE6\n"
                                      "84+UyO9ogT2CNBN7kHqP5LT5iQsX+YzQcJuEmCp8JO6Az/pkErH15p2uLIHHTXRK\n"
                                      "gGrazVRl4Gt4Qdx4dGk/WcTK6NDPeoi4Wki1DzzK0fJNUDYHItycZDK1bfY+2n+Q\n"
                                      "C5d40kIR4oRdHC0VF94clXuTD/Z7tpgN2vXODP9IlwKCAQAJVxUlmATuqhNRgxNN\n"
                                      "15Cpv+aAfljD2aYyReEADtBNMBjEmES2gi8yzdS9JQTc+02kGx2h2guFXNHDgHxV\n"
                                      "eNrKPq8sMMNB4XXl9AFilBSE7dFDBb2HAOP4fiudHQ5HBFf45bK05vwzse8pi8Om\n"
                                      "3qVt2Q0SjJ2uK1UFTKFKIpNxpttl4H+dbe8VAaCjHwY5E6LCuXPoGFIiB7b0ZkMa\n"
                                      "2uHFv/tomUfU98oCafmxu1bBwf+dW1+iyaLATv+/Vg+LWeZjOqJFck2wYSQRGqqp\n"
                                      "kShu0kOZ9UCUPZvAzdzlD96hHG0kN+arRf/i3ZtLJa5ltkwt7ghyTXI1G4PsOZq2\n"
                                      "8FIhAoIBAEYUf2n6FgIDt5s9ritnuiZC7FgkM1yqA3W8ZwK4MFpM/Wac1umJgUSv\n"
                                      "4JYUnv61zT1rF2FHh/c5v0/paM1deZq5C3XowL+DA65WYzevdp0/AtMNsiTZwPrw\n"
                                      "ZPYz22KcZUzkBUToC0gXuoNUaAoDbmiO7xKkRbAH9wQZcyrP9/WcTR0QgPOzrND7\n"
                                      "DO3y7xOiY9BvYnzzaFhOfcrDanMxPXVpYuTjT57NKwPcr6xQ/mRKKziOzoQ32dAG\n"
                                      "lbcIqvwRwz/T/bnJGTo4Xb64/y6QUFxcZf7NceujB68tK14XSg6mBEtIvrJXz0xq\n"
                                      "x6/mFWYJZTDtHKuWusgCHkmN2LL9iwMCggEAW00XBAIhaMskQh4TiBk8e2n8mBw3\n"
                                      "oqdRPgJ4LWLEdBxYJKoQCffyGW47qZXEvb416r5mq1XwHJlrYUqcf63Lj3ANAt+8\n"
                                      "ifE/FUhwb8jAiji6XTicDJERkM5HrxDA3TS2pbBM2/bIurOzBXGpXNpnMLKbNCur\n"
                                      "bvS5UcsSO5OvRH7JT4E5AwuuNPoiZb3nY/1wlC9VfzAc4tw5W1gMoElkiG1QxsMV\n"
                                      "ip5M37v06Exj2YURmRzIfhOGNgTf9NA91FZb73t94sUqxT0JbiWSA3llXKJn+NYr\n"
                                      "J04EngxPgHewJPwWf50GzLPK62OMKd7O5deTw+HO7qrClcpExZGsakc/cw==\n"
                                      "-----END RSA PRIVATE KEY-----";

static const char RSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                     "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWFe7BbX1nWo5oaSv/Jv\n"
                                     "IUCWsk/Vi2q8P0cGkefgN5J7MN7Kfv7lq0hl/1cZcJs81IC+GiC+V3aR2zLBNnJJ\n"
                                     "axa4sqk+hF5DJcD2bF0B80uqPYQUXlQwki/heATnVcke8APuY0kOZykxoD0APAqw\n"
                                     "0z5KDqgt2vA9G6keM6b9bbL+IvxM+yMk1QV0OQLh6Rkz46DyPSoUFWyXiist47PJ\n"
                                     "KNyZAfFZx6vEivzBmqRHKe11W9oD/tN5VTQCH/UTSRfyWq/UUMFVMCksLwT6XoWI\n"
                                     "7F5swgQkSahWkVJ93Qf8cUf1HIZYTMJBYPG4y2NDZ0+ytnH3BNXLMQXg9xbgv6B/\n"
                                     "iaSVScI4CWIpQTAtNKnJwYg2+RhfYBC07iM56c4a+TjbCWgmd11UYc96dbw83uFR\n"
                                     "jKZc3+SC38ITCgMuoDPNBlFJK6u8VfYylGEJolGcauVa6yZKwzsJGr5J/LANz+Zy\n"
                                     "HZmANed+2Hjqxu/H1NGDBdvUGLQbhb/uBJ8oG8iAW5eUyjEJMX0RuncYnBrUjZdE\n"
                                     "Fr0zJd5VkrfFTd26AjGusbiBevATfj83SNa9uK3N3lSNcLNyNXUjmfOU21NWHAk5\n"
                                     "QV3TJb6SCTcqWFaYoyKR7H6zxRcArNuIAMW4KhOl4jdNnTxJllC4tr/gkE+uO1nt\n"
                                     "B9ymLxQBRp8osHjuZpKXr3cCAwEAAQ==\n"
                                     "-----END PUBLIC KEY-----";

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

}

static void test_l8w8jwt_decode_invalid_signature_rs384(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_rs512(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_ps256(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_ps384(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_ps512(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_es256(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_es384(void** state)
{

}

static void test_l8w8jwt_decode_invalid_signature_es512(void** state)
{

}

// Test signature validity (decode + validation both need to succeed).

static void test_l8w8jwt_decode_valid_signature_hs256(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_hs384(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_hs512(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_rs256(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_rs384(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_rs512(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_ps256(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_ps384(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_ps512(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_es256(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_es384(void** state)
{

}

static void test_l8w8jwt_decode_valid_signature_es512(void** state)
{

}

// Test claims invalidity (decode needs to succeed; validation needs to fail).

static void test_l8w8jwt_decode_invalid_exp(void** state)
{

}

static void test_l8w8jwt_decode_invalid_nbf(void** state)
{

}

static void test_l8w8jwt_decode_invalid_iat(void** state)
{

}

static void test_l8w8jwt_decode_invalid_sub(void** state)
{

}

static void test_l8w8jwt_decode_invalid_iss(void** state)
{

}

static void test_l8w8jwt_decode_invalid_aud(void** state)
{

}

static void test_l8w8jwt_decode_invalid_jti(void** state)
{

}

// Test claims validity (decode + validation successful).

static void test_l8w8jwt_decode_valid_exp(void** state)
{

}

static void test_l8w8jwt_decode_valid_nbf(void** state)
{

}

static void test_l8w8jwt_decode_valid_iat(void** state)
{

}

static void test_l8w8jwt_decode_valid_sub(void** state)
{

}

static void test_l8w8jwt_decode_valid_iss(void** state)
{

}

static void test_l8w8jwt_decode_valid_aud(void** state)
{

}

static void test_l8w8jwt_decode_valid_jti(void** state)
{

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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
