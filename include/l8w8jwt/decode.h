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
 *  @brief Core decode function for l8w8jwt. Use this to decode and verify a JWT's signature!
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
 * Struct containing the parameters to use for decoding and validating a JWT.
 */
struct l8w8jwt_decoding_params
{
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
     * (e.g. if you chose HS256 as algorithm, this will be the HMAC secret WITHOUT NUL-terminator; for RS512 this will be the public RSA key WITH the NUL-terminator, PEM-formatted, etc...).
     */
    unsigned char* verification_key;

    /**
     * Length of the {@link #verification_key}
     */
    size_t verification_key_length;
};

// TODO: write the decode function!
int l8w8jwt_decode();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_DECODE_H
