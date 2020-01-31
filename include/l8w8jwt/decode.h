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

/**
 *  @file decode.h
 *  @author Raphael Beck
 *  @brief Core DECODE function for l8w8jwt. Use this to decode and validate a JWT!
 */

#ifndef L8W8JWT_DECODE_H
#define L8W8JWT_DECODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdbool.h>
#include "l8w8jwt/algs.h"
#include "l8w8jwt/claim.h"
#include "l8w8jwt/retcodes.h"

/**
 * Enum containing the validation result flags.
 */
enum l8w8jwt_validation_result
{
    /**
     * The JWT is valid (according to the passed validation parameters).
     */
    L8W8JWT_VALID = 0,

    /**
     * The issuer claim is invalid.
     */
    L8W8JWT_ISS_FAILURE = 1 << 0,

    /**
     * The subject claim is invalid.
     */
    L8W8JWT_SUB_FAILURE = 1 << 1,

    /**
     * The audience claim is invalid.
     */
    L8W8JWT_AUD_FAILURE = 1 << 2,

    /**
     * The JWT ID claim is invalid.
     */
    L8W8JWT_JTI_FAILURE = 1 << 3,

    /**
     * The token is expired.
     */
    L8W8JWT_EXP_FAILURE = 1 << 4,

    /**
     * The token is not yet valid.
     */
    L8W8JWT_NBF_FAILURE = 1 << 5,

    /**
     * The token was not issued yet, are you from the future?
     */
    L8W8JWT_IAT_FAILURE = 1 << 6,

    /**
     * The token was potentially tampered with: its signature couldn't be verified.
     */
    L8W8JWT_SIGNATURE_VERIFICATION_FAILURE = 1 << 7
};

/**
 * Struct containing the parameters to use for decoding and validating a JWT.
 */
struct l8w8jwt_decoding_params
{
    /**
     * The token to decode and validate.
     */
    char* jwt;

    /**
     * The jwt string length.
     */
    size_t jwt_length;

    /**
     * The signature algorithm ID. <p>
     * [0;2] = HS256/384/512 | [3;5] = RS256/384/512 | [6;8] = PS256/384/512 | [9;11] = ES256/384/512 <p>
     * This affects what should be the value of {@link #verification_key}
     */
    int alg;

    /**
     * [OPTIONAL] The issuer claim (who issued the JWT?). <p>
     * Set to <code>NULL</code> if you don't want to validate the issuer. <p>
     * The JWT will only pass verification if its <code>iss</code> claim matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    char* validate_iss;

    /**
     * validate_iss string length.
     */
    size_t validate_iss_length;

    /**
     * [OPTIONAL] The subject claim (who is the JWT about?). <p>
     * Set to <code>NULL</code> if you don't want to validate the subject claim. <p>
     * The JWT will only pass verification if its <code>sub</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    char* validate_sub;

    /**
     * validate_sub string length.
     */
    size_t validate_sub_length;

    /**
     * [OPTIONAL] The audience claim (who is the JWT intended for? Who is the intended JWT's recipient?). <p>
     * Set to <code>NULL</code> if you don't want to validate the audience. <p>
     * The JWT will only pass verification if its <code>aud</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    char* validate_aud;

    /**
     * validate_aud string length.
     */
    size_t validate_aud_length;

    /**
     * [OPTIONAL] The JWT ID. Provides a unique identifier for the token. <p>
     * Set to <code>NULL</code> if you don't want to validate the jti claim. <p>
     * The JWT will only pass verification if its <code>jti</code> matches this string.
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    char* validate_jti;

    /**
     * validate_jti claim length.
     */
    size_t validate_jti_length;

    /**
     * Should the expiration claim be verified?
     * If this is set to <code>true</code>, the <code>exp</code> claim will be compared to the current date and time + {@link #exp_tolerance_seconds}
     */
    bool validate_exp;

    /**
     * Should the "not before" claim be verified?
     * If this is set to <code>true</code>, the <code>nbf</code> claim will be compared to the current date and time + {@link #nbf_tolerance_seconds}
     */
    bool validate_nbf;

    /**
     * Should the "issued at" claim be verified?
     * If this is set to <code>true</code>, the <code>iat</code> claim will be compared to the current date and time + {@link #iat_tolerance_seconds}
     */
    bool validate_iat;

    /**
     * Small inconsistencies in time can happen, or also latency between clients and servers.
     * That's just life. You can forgive a few seconds of expiration, but don't exaggerate this! <p>
     * Only taken into consideration if {@link #validate_exp} is set to <code>true</code>.
     */
    uint8_t exp_tolerance_seconds;

    /**
     * The amount of seconds to subtract from the current time when comparing the "not before" claim, to allow for a small tolerance time frame.
     * Only taken into consideration if {@link #validate_nbf} is set to <code>true</code>.
     */
    uint8_t nbf_tolerance_seconds;

    /**
     * The amount of seconds to subtract from the current time when comparing the "issued at" claim, to allow for a small tolerance time frame.
     * Only taken into consideration if {@link #validate_iat} is set to <code>true</code>.
     */
    uint8_t iat_tolerance_seconds;

    /**
     * The key to use for verifying the token's signature
     * (e.g. if you chose HS256 as algorithm, this will be the HMAC secret; for RS512 this will be the PEM-formatted public RSA key string, etc...).
     */
    unsigned char* verification_key;

    /**
     * Length of the {@link #verification_key}
     */
    size_t verification_key_length;

    /**
     * [OPTIONAL] Where the decoded claims (header + payload claims together) should be written into. <p>
     * This pointer will be dereferenced + allocated, so make sure to pass a fresh pointer! <p>
     * If you don't need the claims, set this to <code>NULL</code> (they will only be validated, e.g. signature, exp, etc...). <p>
     * @note If you decide to keep the claims in this out parameter, REMEMBER to call {@link #l8w8jwt_free_claims()} on it once you're done using them!
     */
    struct l8w8jwt_claim** out_claims;

    /**
     * Where to write the decoded claims count into. <p>
     * This will receive the value of how many claims were written into "out_claims" (0 if you decided to set "out_claims" to <code>NULL</code>).
     */
    size_t* out_claims_length;
};

/**
 * Validates a set of l8w8jwt_decoding_params.
 * @param params The l8w8jwt_decoding_params to validate.
 * @return Return code as defined in retcodes.h
 */
int l8w8jwt_validate_decoding_params(struct l8w8jwt_decoding_params* params);

/**
 * Decode (and validate) a JWT using specific parameters. <p>
 * The resulting l8w8jwt_validation_result written into the passed "out" pointer
 * contains validation failure flags (see the {@link #l8w8jwt_validation_result} enum docs for more details). <p>
 * This only happens if decoding also succeeded: if the token is malformed, nothing will be written into "out". <p>
 * If validation succeeds, the l8w8jwt_validation_result receives the value 0 (enum value <code>L8W8JWT_VALID</code>).
 * @param params The parameters to use for decoding and validating the token.
 * @param out Where to write the validation result flags into (0 means success).
 * @return Return code as defined in retcodes.h
 */
int l8w8jwt_decode(struct l8w8jwt_decoding_params* params, enum l8w8jwt_validation_result* out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_DECODE_H
