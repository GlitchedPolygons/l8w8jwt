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

#include "l8w8jwt/encode.h"
#include "l8w8jwt/base64.h"
#include "l8w8jwt/retcodes.h"

#include <stdbool.h>
#include <inttypes.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/asn1write.h>

static int write_header_and_payload(chillbuff* stringbuilder, struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff buff;

    r = chillbuff_init(&buff, 256, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    switch (params->alg)
    {
        case L8W8JWT_ALG_HS256:
            chillbuff_push_back(&buff, "{\"alg\":\"HS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_HS384:
            chillbuff_push_back(&buff, "{\"alg\":\"HS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_HS512:
            chillbuff_push_back(&buff, "{\"alg\":\"HS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS256:
            chillbuff_push_back(&buff, "{\"alg\":\"RS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS384:
            chillbuff_push_back(&buff, "{\"alg\":\"RS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_RS512:
            chillbuff_push_back(&buff, "{\"alg\":\"RS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS256:
            chillbuff_push_back(&buff, "{\"alg\":\"PS256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS384:
            chillbuff_push_back(&buff, "{\"alg\":\"PS384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_PS512:
            chillbuff_push_back(&buff, "{\"alg\":\"PS512\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES256:
            chillbuff_push_back(&buff, "{\"alg\":\"ES256\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES384:
            chillbuff_push_back(&buff, "{\"alg\":\"ES384\",\"typ\":\"JWT\"", 26);
            break;
        case L8W8JWT_ALG_ES512:
            chillbuff_push_back(&buff, "{\"alg\":\"ES512\",\"typ\":\"JWT\"", 26);
            break;
        default:
            chillbuff_free(&buff);
            return L8W8JWT_INVALID_ARG;
    }

    if (params->additional_header_claims_count > 0)
    {
        chillbuff_push_back(&buff, ",", 1);
        l8w8jwt_write_claims(&buff, params->additional_header_claims, params->additional_header_claims_count);
    }

    chillbuff_push_back(&buff, "}", 1);

    char* segment;
    size_t segment_length;

    r = l8w8jwt_base64_encode(true, buff.array, buff.length, &segment, &segment_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&buff);
        return r;
    }

    chillbuff_push_back(stringbuilder, segment, segment_length);

    free(segment);
    segment = NULL;
    chillbuff_clear(&buff);

    char iatnbfexp[64];
    memset(iatnbfexp, '\0', sizeof(iatnbfexp));

    if (params->iat)
    {
        snprintf(iatnbfexp + 00, 21, "%" PRIu64 "", (uint64_t)params->iat);
    }

    if (params->nbf)
    {
        snprintf(iatnbfexp + 21, 21, "%" PRIu64 "", (uint64_t)params->nbf);
    }

    if (params->exp)
    {
        snprintf(iatnbfexp + 42, 21, "%" PRIu64 "", (uint64_t)params->exp);
    }

    struct l8w8jwt_claim claims[] = {
        // Setting l8w8jwt_claim::value_length to 0 makes the encoder use strlen, which in this case is fine.
        { .key = *(iatnbfexp + 00) ? "iat" : NULL, .key_length = 3, .value = iatnbfexp + 00, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = *(iatnbfexp + 21) ? "nbf" : NULL, .key_length = 3, .value = iatnbfexp + 21, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = *(iatnbfexp + 42) ? "exp" : NULL, .key_length = 3, .value = iatnbfexp + 42, .value_length = 0, .type = L8W8JWT_CLAIM_TYPE_INTEGER },
        { .key = params->sub ? "sub" : NULL, .key_length = 3, .value = params->sub, .value_length = params->sub_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->iss ? "iss" : NULL, .key_length = 3, .value = params->iss, .value_length = params->iss_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->aud ? "aud" : NULL, .key_length = 3, .value = params->aud, .value_length = params->aud_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
        { .key = params->jti ? "jti" : NULL, .key_length = 3, .value = params->jti, .value_length = params->jti_length, .type = L8W8JWT_CLAIM_TYPE_STRING },
    };

    chillbuff_push_back(&buff, "{", 1);

    l8w8jwt_write_claims(&buff, claims, sizeof(claims) / sizeof(struct l8w8jwt_claim));

    if (params->additional_payload_claims_count > 0)
    {
        chillbuff_push_back(&buff, ",", 1);
        l8w8jwt_write_claims(&buff, params->additional_payload_claims, params->additional_payload_claims_count);
    }

    chillbuff_push_back(&buff, "}", 1);

    r = l8w8jwt_base64_encode(true, buff.array, buff.length, &segment, &segment_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&buff);
        return r;
    }

    chillbuff_push_back(stringbuilder, ".", 1);
    chillbuff_push_back(stringbuilder, segment, segment_length);

    free(segment);
    chillbuff_free(&buff);

    return L8W8JWT_SUCCESS;
}

static int jwt_hs(struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff stringbuilder;

    r = chillbuff_init(&stringbuilder, 256, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    r = write_header_and_payload(&stringbuilder, params);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    uint8_t signature_bytes[64];
    const mbedtls_md_info_t* info = params->alg == L8W8JWT_ALG_HS256 ? &mbedtls_sha256_info : params->alg == L8W8JWT_ALG_HS384 ? &mbedtls_sha384_info : &mbedtls_sha512_info;

    r = mbedtls_md_hmac(info, params->secret_key, params->secret_key_length, (const unsigned char*)stringbuilder.array, stringbuilder.length, (unsigned char*)signature_bytes);
    if (r != 0)
    {
        chillbuff_free(&stringbuilder);
        return L8W8JWT_SIGNATURE_FAILURE;
    }

    char* signature;
    size_t signature_length;

    r = l8w8jwt_base64_encode(true, signature_bytes, 32 + (16 * params->alg), &signature, &signature_length);
    if (r != L8W8JWT_SUCCESS)
    {
        chillbuff_free(&stringbuilder);
        return r;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature, signature_length);

    free(signature);

    *(params->out) = malloc(stringbuilder.length + 1);
    if (*(params->out) == NULL)
    {
        chillbuff_free(&stringbuilder);
        return L8W8JWT_OUT_OF_MEM;
    }

    *(params->out_length) = stringbuilder.length;
    (*(params->out))[stringbuilder.length] = '\0';
    memcpy(*(params->out), stringbuilder.array, stringbuilder.length);

    chillbuff_free(&stringbuilder);
    return L8W8JWT_SUCCESS;
}

static int jwt_rs(struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff stringbuilder;

    if (params->secret_key_length > 8192)
    {
        return L8W8JWT_INVALID_ARG;
    }

    r = chillbuff_init(&stringbuilder, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    unsigned char key[8192];
    memset(key, '\0', sizeof(key));
    memcpy(key, params->secret_key, params->secret_key_length);

    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"l8w8jwt_mbedtls_pers.!#@", 24);
    if (r != 0)
    {
        r = L8W8JWT_MBEDTLS_CTR_DRBG_SEED_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_parse_key(&ctx, key, strlen((const char*)key) + 1, params->secret_key_pw, params->secret_key_pw_length);
    if (r != 0)
    {
        r = L8W8JWT_KEY_PARSE_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_get_type(&ctx);
    if (r != MBEDTLS_PK_RSA && r != MBEDTLS_PK_RSA_ALT && !mbedtls_pk_can_do(&ctx, MBEDTLS_PK_RSA) && !mbedtls_pk_can_do(&ctx, MBEDTLS_PK_RSA_ALT))
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    if (mbedtls_pk_get_bitlen(&ctx) < 2048) /* Weak keys are forbidden! */
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    r = write_header_and_payload(&stringbuilder, params);
    if (r != L8W8JWT_SUCCESS)
    {
        goto exit;
    }

    size_t md_length;
    mbedtls_md_type_t md_type;
    mbedtls_md_info_t* md_info;

    switch (params->alg)
    {
        case L8W8JWT_ALG_RS256:
            md_length = 32;
            md_type = MBEDTLS_MD_SHA256;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha256_info);
            break;
        case L8W8JWT_ALG_RS384:
            md_length = 48;
            md_type = MBEDTLS_MD_SHA384;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha384_info);
            break;
        case L8W8JWT_ALG_RS512:
            md_length = 64;
            md_type = MBEDTLS_MD_SHA512;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha512_info);
            break;
        default:
            r = L8W8JWT_INVALID_ARG;
            goto exit;
    }

    unsigned char hash[64];
    memset(hash, '\0', sizeof(hash));

    /* Hash the JWT header + payload. */
    r = mbedtls_md(md_info, (const unsigned char*)stringbuilder.array, stringbuilder.length, hash);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_SHA2_FAILURE;
        goto exit;
    }

    size_t signature_length;
    unsigned char signature[2048];
    memset(signature, '\0', sizeof(signature));

    /* Sign the hash using the provided private key. */
    r = mbedtls_pk_sign(&ctx, md_type, hash, md_length, signature, &signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_SIGNATURE_FAILURE;
        goto exit;
    }

    char* signature_string;
    size_t signature_string_length;

    /* Base64URL-encode the signature and append the result to the JWT header + payload to finalize the token. */
    r = l8w8jwt_base64_encode(true, (uint8_t*)signature, signature_length, &signature_string, &signature_string_length);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature_string, signature_string_length);

    free(signature_string);

    *(params->out) = malloc(stringbuilder.length + 1);
    if (*(params->out) == NULL)
    {
        r = L8W8JWT_OUT_OF_MEM;
        goto exit;
    }

    *(params->out_length) = stringbuilder.length;
    (*(params->out))[stringbuilder.length] = '\0';
    memcpy(*(params->out), stringbuilder.array, stringbuilder.length);

    r = L8W8JWT_SUCCESS;

exit:
    mbedtls_pk_free(&ctx);
    chillbuff_free(&stringbuilder);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return r;
}

static int jwt_ps(struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff stringbuilder;

    if (params->secret_key_length > 8192)
    {
        return L8W8JWT_INVALID_ARG;
    }

    r = chillbuff_init(&stringbuilder, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    unsigned char key[8192];
    memset(key, '\0', sizeof(key));
    memcpy(key, params->secret_key, params->secret_key_length);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"l8w8jwt_mbedtls_pers.!#@", 24);
    if (r != 0)
    {
        r = L8W8JWT_MBEDTLS_CTR_DRBG_SEED_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_parse_key(&pk, key, strlen((const char*)key) + 1, params->secret_key_pw, params->secret_key_pw_length);
    if (r != 0)
    {
        r = L8W8JWT_KEY_PARSE_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_get_type(&pk);
    if (r != MBEDTLS_PK_RSA && r != MBEDTLS_PK_RSA_ALT && r != MBEDTLS_PK_RSASSA_PSS)
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA) && !mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSASSA_PSS))
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    if (mbedtls_pk_get_bitlen(&pk) < 2048) /* Weak keys are forbidden! */
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    r = write_header_and_payload(&stringbuilder, params);
    if (r != L8W8JWT_SUCCESS)
    {
        goto exit;
    }

    size_t md_length;
    mbedtls_md_type_t md_type;
    mbedtls_md_info_t* md_info;

    switch (params->alg)
    {
        case L8W8JWT_ALG_PS256:
            md_length = 32;
            md_type = MBEDTLS_MD_SHA256;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha256_info);
            break;
        case L8W8JWT_ALG_PS384:
            md_length = 48;
            md_type = MBEDTLS_MD_SHA384;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha384_info);
            break;
        case L8W8JWT_ALG_PS512:
            md_length = 64;
            md_type = MBEDTLS_MD_SHA512;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha512_info);
            break;
        default:
            r = L8W8JWT_INVALID_ARG;
            goto exit;
    }

    unsigned char hash[64];
    memset(hash, '\0', sizeof(hash));

    /* Hash the JWT header + payload. */
    r = mbedtls_md(md_info, (const unsigned char*)stringbuilder.array, stringbuilder.length, hash);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_SHA2_FAILURE;
        goto exit;
    }

    unsigned char signature[4096];
    memset(signature, '\0', sizeof(signature));

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    rsa->hash_id = md_type;
    rsa->padding = MBEDTLS_RSA_PKCS_V21;

    r = mbedtls_rsa_rsassa_pss_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, md_type, md_length, hash, signature);
    if (r != 0)
    {
        r = L8W8JWT_SIGNATURE_FAILURE;
        goto exit;
    }

    char* signature_string;
    size_t signature_string_length;

    /* Base64URL-encode the signature and append the result to the JWT header + payload to finalize the token. */
    r = l8w8jwt_base64_encode(true, (uint8_t*)signature, 512, &signature_string, &signature_string_length);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature_string, signature_string_length);

    free(signature_string);

    *(params->out) = malloc(stringbuilder.length + 1);
    if (*(params->out) == NULL)
    {
        r = L8W8JWT_OUT_OF_MEM;
        goto exit;
    }

    *(params->out_length) = stringbuilder.length;
    (*(params->out))[stringbuilder.length] = '\0';
    memcpy(*(params->out), stringbuilder.array, stringbuilder.length);

    r = L8W8JWT_SUCCESS;

exit:
    mbedtls_pk_free(&pk);
    chillbuff_free(&stringbuilder);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return r;
}

static int jwt_es(struct l8w8jwt_encoding_params* params)
{
    int r;
    chillbuff stringbuilder;

    if (params->secret_key_length > 4096)
    {
        return L8W8JWT_INVALID_ARG;
    }

    r = chillbuff_init(&stringbuilder, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    if (r != CHILLBUFF_SUCCESS)
    {
        return L8W8JWT_OUT_OF_MEM;
    }

    unsigned char key[4096];
    memset(key, '\0', sizeof(key));
    memcpy(key, params->secret_key, params->secret_key_length);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_mpi sig_r, sig_s;
    mbedtls_mpi_init(&sig_r);
    mbedtls_mpi_init(&sig_s);

    r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"l8w8jwt_mbedtls_pers.!#@", 24);
    if (r != 0)
    {
        r = L8W8JWT_MBEDTLS_CTR_DRBG_SEED_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_parse_key(&pk, key, strlen((const char*)key) + 1, params->secret_key_pw, params->secret_key_pw_length);
    if (r != 0)
    {
        r = L8W8JWT_KEY_PARSE_FAILURE;
        goto exit;
    }

    r = mbedtls_pk_get_type(&pk);
    if (r != MBEDTLS_PK_ECKEY && r != MBEDTLS_PK_ECKEY_DH && r != MBEDTLS_PK_ECDSA && !mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA))
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    r = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(pk));
    if (r != 0)
    {
        r = L8W8JWT_KEY_PARSE_FAILURE;
        goto exit;
    }

    r = write_header_and_payload(&stringbuilder, params);
    if (r != L8W8JWT_SUCCESS)
    {
        goto exit;
    }

    int md_length;
    mbedtls_md_type_t md_type;
    mbedtls_md_info_t* md_info;
    size_t signature_length;

    switch (params->alg)
    {
        case L8W8JWT_ALG_ES256:
            md_length = 32;
            md_type = MBEDTLS_MD_SHA256;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha256_info);
            signature_length = 64;
            r = mbedtls_pk_get_bitlen(&pk) == 256;
            break;
        case L8W8JWT_ALG_ES384:
            md_length = 48;
            md_type = MBEDTLS_MD_SHA384;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha384_info);
            signature_length = 96;
            r = mbedtls_pk_get_bitlen(&pk) == 384;
            break;
        case L8W8JWT_ALG_ES512:
            md_length = 64;
            md_type = MBEDTLS_MD_SHA512;
            md_info = (mbedtls_md_info_t*)(&mbedtls_sha512_info);
            signature_length = 132;
            r = mbedtls_pk_get_bitlen(&pk) == 521;
            break;
        default:
            r = L8W8JWT_INVALID_ARG;
            goto exit;
    }

    /* Ensure that the passed key size is valid and compatible with the selected JWT alg. */
    if (!r)
    {
        r = L8W8JWT_WRONG_KEY_TYPE;
        goto exit;
    }

    unsigned char hash[64];
    memset(hash, '\0', sizeof(hash));

    unsigned char signature[256];
    memset(signature, '\0', sizeof(signature));

    const size_t hl = signature_length / 2;

    /* Hash the JWT header + payload. */
    r = mbedtls_md(md_info, (const unsigned char*)stringbuilder.array, stringbuilder.length, hash);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_SHA2_FAILURE;
        goto exit;
    }

    /* Sign the hash using the provided private key. */
    r = mbedtls_ecdsa_sign_det(&ecdsa.grp, &sig_r, &sig_s, &ecdsa.d, hash, md_length, md_type);
    if (r != 0)
    {
        r = L8W8JWT_SIGNATURE_FAILURE;
        goto exit;
    }

    r = mbedtls_mpi_write_binary(&sig_r, signature, hl);
    if (r != 0)
    {
        r = L8W8JWT_SIGNATURE_FAILURE;
        goto exit;
    }

    r = mbedtls_mpi_write_binary(&sig_s, signature + hl, hl);
    if (r != 0)
    {
        r = L8W8JWT_SIGNATURE_FAILURE;
        goto exit;
    }

    char* signature_string;
    size_t signature_string_length;

    /* Base64URL-encode the signature and append the result to the JWT header + payload to finalize the token. */
    r = l8w8jwt_base64_encode(true, (uint8_t*)signature, signature_length, &signature_string, &signature_string_length);
    if (r != L8W8JWT_SUCCESS)
    {
        r = L8W8JWT_BASE64_FAILURE;
        goto exit;
    }

    chillbuff_push_back(&stringbuilder, ".", 1);
    chillbuff_push_back(&stringbuilder, signature_string, signature_string_length);

    free(signature_string);

    *(params->out) = malloc(stringbuilder.length + 1);
    if (*(params->out) == NULL)
    {
        r = L8W8JWT_OUT_OF_MEM;
        goto exit;
    }

    *(params->out_length) = stringbuilder.length;
    (*(params->out))[stringbuilder.length] = '\0';
    memcpy(*(params->out), stringbuilder.array, stringbuilder.length);

    r = L8W8JWT_SUCCESS;

exit:
    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    chillbuff_free(&stringbuilder);
    return r;
}

int validate_encoding_params(struct l8w8jwt_encoding_params* params)
{
    if (params == NULL || params->secret_key == NULL || params->out == NULL || params->out_length == NULL)
    {
        return L8W8JWT_NULL_ARG;
    }

    if (params->secret_key_length == 0)
    {
        return L8W8JWT_INVALID_ARG;
    }

    if ((params->additional_payload_claims != NULL && params->additional_payload_claims_count == 0))
    {
        return L8W8JWT_INVALID_ARG;
    }

    if ((params->additional_header_claims != NULL && params->additional_header_claims_count == 0))
    {
        return L8W8JWT_INVALID_ARG;
    }

    return L8W8JWT_SUCCESS;
}

int encode(struct l8w8jwt_encoding_params* params)
{
    int r = validate_encoding_params(params);
    if (r != L8W8JWT_SUCCESS)
    {
        return r;
    }

    switch (params->alg)
    {
        case L8W8JWT_ALG_HS256:
        case L8W8JWT_ALG_HS384:
        case L8W8JWT_ALG_HS512:
            return jwt_hs(params);

        case L8W8JWT_ALG_RS256:
        case L8W8JWT_ALG_RS384:
        case L8W8JWT_ALG_RS512:
            return jwt_rs(params);

        case L8W8JWT_ALG_PS256:
        case L8W8JWT_ALG_PS384:
        case L8W8JWT_ALG_PS512:
            return jwt_ps(params);

        case L8W8JWT_ALG_ES256:
        case L8W8JWT_ALG_ES384:
        case L8W8JWT_ALG_ES512:
            return jwt_es(params);

        default:
            return L8W8JWT_INVALID_ARG;
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
