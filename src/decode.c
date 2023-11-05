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

#ifdef __cplusplus
extern "C" {
#endif

#define JSMN_STATIC

#include "l8w8jwt/util.h"
#include "l8w8jwt/decode.h"
#include "l8w8jwt/base64.h"

#include <jsmn.h>
#include <string.h>
#include <inttypes.h>
#include <checknum.h>
#include <chillbuff.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#if L8W8JWT_ENABLE_EDDSA
#include <ed25519.h>
#endif

static inline void md_info_from_alg(const int alg, mbedtls_md_info_t** md_info, mbedtls_md_type_t* md_type, size_t* md_length)
{
    switch (alg)
    {
        case L8W8JWT_ALG_HS256:
        case L8W8JWT_ALG_RS256:
        case L8W8JWT_ALG_PS256:
        case L8W8JWT_ALG_ES256:
        case L8W8JWT_ALG_ES256K:
            *md_length = 32;
            *md_type = MBEDTLS_MD_SHA256;
            *md_info = (mbedtls_md_info_t*)mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;

        case L8W8JWT_ALG_HS384:
        case L8W8JWT_ALG_RS384:
        case L8W8JWT_ALG_PS384:
        case L8W8JWT_ALG_ES384:
            *md_length = 48;
            *md_type = MBEDTLS_MD_SHA384;
            *md_info = (mbedtls_md_info_t*)mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;

        case L8W8JWT_ALG_HS512:
        case L8W8JWT_ALG_RS512:
        case L8W8JWT_ALG_PS512:
        case L8W8JWT_ALG_ES512:
        case L8W8JWT_ALG_ED25519:
            *md_length = 64;
            *md_type = MBEDTLS_MD_SHA512;
            *md_info = (mbedtls_md_info_t*)mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;

        default:
            break;
    }
}

static int l8w8jwt_unescape_claim(struct l8w8jwt_claim* claim, const char* key, const size_t key_length, const char* value, const size_t value_length)
{
    claim->key_length = 0;
    claim->key = calloc(sizeof(char), key_length + 1);

    claim->value_length = 0;
    claim->value = calloc(sizeof(char), value_length + 1);

    if (claim->key == NULL || claim->value == NULL)
    {
        free(claim->key);
        free(claim->value);
        return L8W8JWT_OUT_OF_MEM;
    }

    char* out_key = claim->key;
    char* out_value = claim->value;

    for (size_t i = 0; i < key_length; ++i)
    {
        const char c = key[i];
        *out_key = c;

        if (c == '\\' && i != key_length - 1)
        {
            const char nc = key[i + 1];
            if (nc == '\"')
            {
                *out_key = '\"';
            }
            ++i;
        }

        ++out_key;
    }

    for (size_t i = 0; i < value_length; ++i)
    {
        const char c = value[i];
        *out_value = c;

        if (c == '\\' && i != value_length - 1)
        {
            const char nc = value[i + 1];

            switch (nc)
            {
                case '\"':
                    *out_value = '\"';
                    break;
                case '/':
                    *out_value = '/';
                    break;
                default:
                    break;
            }

            ++i;
        }

        ++out_value;
    }

    claim->key_length = (size_t)(out_key - claim->key);
    claim->value_length = (size_t)(out_value - claim->value);

    return L8W8JWT_SUCCESS;
}

static int l8w8jwt_parse_claims(chillbuff* buffer, char* json, const size_t json_length)
{
    jsmn_parser parser;
    jsmn_init(&parser);

    int r = jsmn_parse(&parser, json, json_length, NULL, 0);

    if (r == 0)
    {
        return L8W8JWT_SUCCESS;
    }
    else if (r < 0)
    {
        return L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
    }

    jsmntok_t _tokens[64];
    jsmntok_t* tokens = r <= (sizeof(_tokens) / sizeof(_tokens[0])) ? _tokens : malloc(r * sizeof(jsmntok_t));

    if (tokens == NULL)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    jsmn_init(&parser);
    r = jsmn_parse(&parser, json, json_length, tokens, r);

    if (r < 0)
    {
        return L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
    }

    if (tokens->type != JSMN_OBJECT)
    {
        r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
        goto exit;
    }

    for (size_t i = 1; i < r; ++i)
    {
        struct l8w8jwt_claim claim;

        const jsmntok_t key = tokens[i];
        const jsmntok_t value = tokens[++i];

        if (i >= r || key.type != JSMN_STRING)
        {
            r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
            goto exit;
        }

        switch (value.type)
        {
            case JSMN_UNDEFINED: {
                claim.type = L8W8JWT_CLAIM_TYPE_OTHER;
                break;
            }
            case JSMN_OBJECT: {
                claim.type = L8W8JWT_CLAIM_TYPE_OBJECT;
                break;
            }
            case JSMN_ARRAY: {
                claim.type = L8W8JWT_CLAIM_TYPE_ARRAY;
                break;
            }
            case JSMN_STRING: {
                claim.type = L8W8JWT_CLAIM_TYPE_STRING;
                break;
            }
            case JSMN_PRIMITIVE: {
                const int value_length = value.end - value.start;

                if (value_length <= 5 && (strncmp(json + value.start, "true", 4) == 0 || strncmp(json + value.start, "false", 5) == 0))
                {
                    claim.type = L8W8JWT_CLAIM_TYPE_BOOLEAN;
                    break;
                }

                if (value_length == 4 && strncmp(json + value.start, "null", 4) == 0)
                {
                    claim.type = L8W8JWT_CLAIM_TYPE_NULL;
                    break;
                }

                switch (checknum(json + value.start, value_length))
                {
                    case 1: {
                        claim.type = L8W8JWT_CLAIM_TYPE_INTEGER;
                        break;
                    }
                    case 2: {
                        claim.type = L8W8JWT_CLAIM_TYPE_NUMBER;
                        break;
                    }
                    default: {
                        r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
                        goto exit;
                    }
                }

                break;
            }
            default: {
                r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
                goto exit;
            }
        }

        int ur = l8w8jwt_unescape_claim(&claim, json + key.start, (size_t)key.end - key.start, json + value.start, (size_t)value.end - value.start);
        if (ur != L8W8JWT_SUCCESS)
        {
            r = ur;
            goto exit;
        }

        chillbuff_push_back(buffer, &claim, 1);
    }

    r = L8W8JWT_SUCCESS;
exit:
    if (tokens != _tokens)
    {
        l8w8jwt_free(tokens);
    }
    return r;
}

void l8w8jwt_decoding_params_init(struct l8w8jwt_decoding_params* params)
{
    if (params == NULL)
    {
        return;
    }
    memset(params, 0x00, sizeof(struct l8w8jwt_decoding_params));
    params->alg = -2;
}

int l8w8jwt_validate_decoding_params(struct l8w8jwt_decoding_params* params)
{
    if (params == NULL || params->jwt == NULL || params->verification_key == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    if (params->jwt_length == 0 || params->verification_key_length == 0 || params->verification_key_length > L8W8JWT_MAX_KEY_SIZE)
    {
        return L8W8JWT_INVALID_ARG;
    }

#if !L8W8JWT_ENABLE_EDDSA
    if (params->alg == L8W8JWT_ALG_ED25519)
    {
        return L8W8JWT_UNSUPPORTED_ALG;
    }
#endif

    return L8W8JWT_SUCCESS;
}

int l8w8jwt_decode(struct l8w8jwt_decoding_params* params, enum l8w8jwt_validation_result* out_validation_result, struct l8w8jwt_claim** out_claims, size_t* out_claims_length)
{
    if (params == NULL || (out_claims != NULL && out_claims_length == NULL))
    {
        return L8W8JWT_NULL_ARG;
    }

    const int alg = params->alg;
    enum l8w8jwt_validation_result validation_res = L8W8JWT_VALID;

    int r = l8w8jwt_validate_decoding_params(params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    if (out_validation_result == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    *out_validation_result = ~L8W8JWT_VALID;

    char* header = NULL;
    size_t header_length = 0;

    char* payload = NULL;
    size_t payload_length = 0;

    uint8_t* signature = NULL;
    size_t signature_length = 0;

    char* current = params->jwt;
    char* next = strchr(params->jwt, '.');

    if (next == NULL) /* No payload. */
    {
        return L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
    }

    int is_cert = 0; // If the validation PEM is a X.509 certificate, this will be set to 1.

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

#if L8W8JWT_SMALL_STACK
    unsigned char* key = calloc(sizeof(unsigned char), L8W8JWT_MAX_KEY_SIZE);
    if (key == NULL)
    {
        r = L8W8JWT_OUT_OF_MEM;
        goto exit;
    }
#else
    unsigned char key[L8W8JWT_MAX_KEY_SIZE] = { 0x00 };
#endif

    size_t key_length = params->verification_key_length;
    memcpy(key, params->verification_key, key_length);

    key_length += key[key_length - 1] != '\0';

    chillbuff claims;
    r = chillbuff_init(&claims, 16, sizeof(struct l8w8jwt_claim), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        r = L8W8JWT_OUT_OF_MEM;
        goto exit;
    }

    size_t current_length = next - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)&header, &header_length);
    if (r != L8W8JWT_SUCCESS)
    {
        if (r != L8W8JWT_OUT_OF_MEM)
            r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    current = next + 1;
    next = strchr(current, '.');

    if (next == NULL && alg != -1) /* No signature. */
    {
        r = L8W8JWT_DECODE_FAILED_MISSING_SIGNATURE;
        goto exit;
    }

    current_length = (next != NULL ? next : params->jwt + params->jwt_length) - current;

    r = l8w8jwt_base64_decode(true, current, current_length, (uint8_t**)&payload, &payload_length);
    if (r != L8W8JWT_SUCCESS)
    {
        if (r != L8W8JWT_OUT_OF_MEM)
            r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    if (next != NULL)
    {
        current = next + 1;
        current_length = (params->jwt + params->jwt_length) - current;

        r = l8w8jwt_base64_decode(true, current, current_length, &signature, &signature_length);
        if (r != L8W8JWT_SUCCESS)
        {
            if (r != L8W8JWT_OUT_OF_MEM)
                r = L8W8JWT_BASE64_FAILURE;
            goto exit;
        }
    }

    /* Signature verification. */
    if (signature != NULL && signature_length > 0 && alg != -1)
    {
        is_cert = strstr((const char*)key, "-----BEGIN CERTIFICATE-----") != NULL;
        if (is_cert)
        {
            r = mbedtls_x509_crt_parse(&crt, key, key_length);
            if (r != 0)
            {
                r = L8W8JWT_KEY_PARSE_FAILURE;
                goto exit;
            }

            pk = crt.pk;
        }

        size_t md_length = 0;
        mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
        mbedtls_md_info_t* md_info = NULL;

        md_info_from_alg(alg, &md_info, &md_type, &md_length);

        unsigned char hash[64] = { 0x00 };

        switch (alg)
        {
            case L8W8JWT_ALG_ES256:
            case L8W8JWT_ALG_ES384:
            case L8W8JWT_ALG_ES512:
            case L8W8JWT_ALG_RS256:
            case L8W8JWT_ALG_RS384:
            case L8W8JWT_ALG_RS512:
            case L8W8JWT_ALG_PS256:
            case L8W8JWT_ALG_PS384:
            case L8W8JWT_ALG_PS512:
            case L8W8JWT_ALG_ES256K: {

                r = mbedtls_md(md_info, (const unsigned char*)params->jwt, (current - 1) - params->jwt, hash);
                if (r != L8W8JWT_SUCCESS)
                {
                    r = L8W8JWT_SHA2_FAILURE;
                    goto exit;
                }
                break;
            }
            default:
                break;
        }

        switch (alg)
        {
            case L8W8JWT_ALG_HS256:
            case L8W8JWT_ALG_HS384:
            case L8W8JWT_ALG_HS512: {

                unsigned char signature_cmp[64];
                memset(signature_cmp, '\0', sizeof(signature_cmp));

                r = mbedtls_md_hmac(md_info, key, key_length - 1, (const unsigned char*)params->jwt, (current - 1) - params->jwt, signature_cmp);
                if (r != 0)
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                r = memcmp(signature, signature_cmp, 32 + (16 * alg));
                if (r != 0)
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;
            }
            case L8W8JWT_ALG_RS256:
            case L8W8JWT_ALG_RS384:
            case L8W8JWT_ALG_RS512: {

                if (!is_cert)
                {
                    r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                    if (r != 0)
                    {
                        r = L8W8JWT_KEY_PARSE_FAILURE;
                        goto exit;
                    }
                }

                r = mbedtls_pk_verify(&pk, md_type, hash, md_length, (const unsigned char*)signature, signature_length);
                if (r != 0)
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;
            }
            case L8W8JWT_ALG_PS256:
            case L8W8JWT_ALG_PS384:
            case L8W8JWT_ALG_PS512: {

                if (!is_cert)
                {
                    r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                    if (r != 0)
                    {
                        r = L8W8JWT_KEY_PARSE_FAILURE;
                        goto exit;
                    }
                }

                mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
                mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md_type);

                r = mbedtls_rsa_rsassa_pss_verify(rsa, md_type, md_length, hash, signature);
                if (r != 0)
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;
            }
            case L8W8JWT_ALG_ES256:
            case L8W8JWT_ALG_ES256K:
            case L8W8JWT_ALG_ES384:
            case L8W8JWT_ALG_ES512: {

                if (!is_cert)
                {
                    r = mbedtls_pk_parse_public_key(&pk, key, key_length);
                    if (r != 0)
                    {
                        r = L8W8JWT_KEY_PARSE_FAILURE;
                        goto exit;
                    }
                }

                const size_t half_signature_length = signature_length / 2;

                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);

                mbedtls_mpi sig_r, sig_s;
                mbedtls_mpi_init(&sig_r);
                mbedtls_mpi_init(&sig_s);

                r = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(pk));

                if (r != 0)
                {
                    r = L8W8JWT_KEY_PARSE_FAILURE;
                    mbedtls_ecdsa_free(&ecdsa);
                    mbedtls_mpi_free(&sig_r);
                    mbedtls_mpi_free(&sig_s);
                    goto exit;
                }

                mbedtls_mpi_read_binary(&sig_r, signature, half_signature_length);
                mbedtls_mpi_read_binary(&sig_s, signature + half_signature_length, half_signature_length);

                r = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, md_length, &ecdsa.MBEDTLS_PRIVATE(Q), &sig_r, &sig_s);
                if (r != 0)
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                }

                mbedtls_ecdsa_free(&ecdsa);
                mbedtls_mpi_free(&sig_r);
                mbedtls_mpi_free(&sig_s);

                break;
            }
            case L8W8JWT_ALG_ED25519: {

#if L8W8JWT_ENABLE_EDDSA
                if (key_length != 64 && !(key_length == 65 && key[64] == 0x00))
                {
                    r = L8W8JWT_WRONG_KEY_TYPE;
                    goto exit;
                }

                unsigned char public_key[32 + 1] = { 0x00 };

                if (l8w8jwt_hexstr2bin((const char*)key, key_length, public_key, sizeof(public_key), NULL) != 0)
                {
                    r = L8W8JWT_WRONG_KEY_TYPE;
                    goto exit;
                }

                if (!ed25519_verify(signature, (const unsigned char*)params->jwt, (current - 1) - params->jwt, public_key))
                {
                    validation_res |= (unsigned)L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;
                    break;
                }

                break;
#else
                r = L8W8JWT_UNSUPPORTED_ALG;
                goto exit;
#endif
            }
            default:
                break;
        }
    }

    r = l8w8jwt_parse_claims(&claims, header, header_length);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
        goto exit;
    }

    r = l8w8jwt_parse_claims(&claims, payload, payload_length);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT;
        goto exit;
    }

    if (params->validate_sub != NULL)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "sub", 3);
        if (c == NULL || strncmp(c->value, params->validate_sub, params->validate_sub_length ? params->validate_sub_length : strlen(params->validate_sub)) != 0)
        {
            validation_res |= (unsigned)L8W8JWT_SUB_FAILURE;
        }
    }

    if (params->validate_aud != NULL)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "aud", 3);
        if (c == NULL || strncmp(c->value, params->validate_aud, params->validate_aud_length ? params->validate_aud_length : strlen(params->validate_aud)) != 0)
        {
            validation_res |= (unsigned)L8W8JWT_AUD_FAILURE;
        }
    }

    if (params->validate_iss != NULL)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "iss", 3);
        if (c == NULL || strncmp(c->value, params->validate_iss, params->validate_iss_length ? params->validate_iss_length : strlen(params->validate_iss)) != 0)
        {
            validation_res |= (unsigned)L8W8JWT_ISS_FAILURE;
        }
    }

    if (params->validate_jti != NULL)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "jti", 3);
        if (c == NULL || strncmp(c->value, params->validate_jti, params->validate_jti_length ? params->validate_jti_length : strlen(params->validate_jti)) != 0)
        {
            validation_res |= (unsigned)L8W8JWT_JTI_FAILURE;
        }
    }

    const l8w8jwt_time_t ct = l8w8jwt_time(NULL);

    if (params->validate_exp)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "exp", 3);
        if (c == NULL || ct - params->exp_tolerance_seconds > strtoll(c->value, NULL, 10))
        {
            validation_res |= (unsigned)L8W8JWT_EXP_FAILURE;
        }
    }

    if (params->validate_nbf)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "nbf", 3);
        if (c == NULL || ct + params->nbf_tolerance_seconds < strtoll(c->value, NULL, 10))
        {
            validation_res |= (unsigned)L8W8JWT_NBF_FAILURE;
        }
    }

    if (params->validate_iat)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "iat", 3);
        if (c == NULL || ct + params->iat_tolerance_seconds < strtoll(c->value, NULL, 10))
        {
            validation_res |= (unsigned)L8W8JWT_IAT_FAILURE;
        }
    }

    if (params->validate_typ)
    {
        struct l8w8jwt_claim* c = l8w8jwt_get_claim(claims.array, claims.length, "typ", 3);
        if (c == NULL || l8w8jwt_strncmpic(c->value, params->validate_typ, params->validate_typ_length) != 0)
        {
            validation_res |= (unsigned)L8W8JWT_TYP_FAILURE;
        }
    }

    r = L8W8JWT_SUCCESS;
    *out_validation_result = validation_res;

    if (out_claims != NULL && out_claims_length != NULL)
    {
        *out_claims_length = claims.length;
        *out_claims = (struct l8w8jwt_claim*)claims.array;
    }

exit:
    l8w8jwt_free(header);
    l8w8jwt_free(payload);
    l8w8jwt_free(signature);

    if (out_claims == NULL || r != L8W8JWT_SUCCESS)
    {
        l8w8jwt_free_claims((struct l8w8jwt_claim*)claims.array, claims.length);
    }

    mbedtls_platform_zeroize(key, L8W8JWT_MAX_KEY_SIZE);
#if L8W8JWT_SMALL_STACK
    l8w8jwt_free(key);
#endif

    if (is_cert)
    {
        mbedtls_x509_crt_free(&crt);
    }
    else
    {
        mbedtls_pk_free(&pk);
    }

    return r;
}

#undef JSMN_STATIC

#ifdef __cplusplus
} // extern "C"
#endif
