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
 *  @file retcodes.h
 *  @author Raphael Beck
 *  @brief Macros for possible integer codes returned by the various l8w8jwt functions.
 */

#ifndef L8W8JWT_RETCODES_H
#define L8W8JWT_RETCODES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returned from a l8w8jwt function when everything went smooth 'n' chill. Time to get Schwifty, Morteyy!
 */
#define L8W8JWT_SUCCESS 0

/**
 * Error code returned by a l8w8jwt function if you passed a NULL argument that shouldn't have been NULL.
 */
#define L8W8JWT_NULL_ARG 100

/**
 * This error code is returned by a l8w8jwt function if you passed an invalid parameter into it.
 */
#define L8W8JWT_INVALID_ARG 200

/**
 * This is returned if some allocation inside a l8w8jwt function failed: you're out of memory at this point.
 */
#define L8W8JWT_OUT_OF_MEM 300

/**
 * Not good...
 */
#define L8W8JWT_OVERFLOW 310

/**
 * Returned if signing a JWT using the HMAC + SHA256 algorithm failed.
 */
#define L8W8JWT_HS256_SIGNATURE_FAILURE 400

/**
 * Returned if signing a JWT using the HMAC + SHA384 algorithm failed.
 */
#define L8W8JWT_HS384_SIGNATURE_FAILURE 500

/**
 * Returned if signing a JWT using the HMAC + SHA512 algorithm failed.
 */
#define L8W8JWT_HS512_SIGNATURE_FAILURE 600

/**
 * Returned if signing a JWT using the RSASSA-PKCS1-v1_5 + SHA256 algorithm failed.
 */
#define L8W8JWT_RS256_SIGNATURE_FAILURE 700

/**
 * Returned if signing a JWT using the RSASSA-PKCS1-v1_5 + SHA384 algorithm failed.
 */
#define L8W8JWT_RS384_SIGNATURE_FAILURE 800

/**
 * Returned if signing a JWT using the RSASSA-PKCS1-v1_5 + SHA512 algorithm failed.
 */
#define L8W8JWT_RS512_SIGNATURE_FAILURE 900

/**
 * Returned if signing a JWT using the ECDSA + P-256 + SHA256 algorithm failed.
 */
#define L8W8JWT_ES256_SIGNATURE_FAILURE 1000

/**
 * Returned if signing a JWT using the ECDSA + P-384 + SHA384 algorithm failed.
 */
#define L8W8JWT_ES384_SIGNATURE_FAILURE 1100

/**
 * Returned if signing a JWT using the ECDSA + P-521 + SHA512 algorithm failed.
 */
#define L8W8JWT_ES512_SIGNATURE_FAILURE 1200

/**
 * Returned if signing a JWT using the RSASSA-PSS MGF1 SHA-256 algorithm failed.
 */
#define L8W8JWT_PS256_SIGNATURE_FAILURE 1300

/**
 * Returned if signing a JWT using the RSASSA-PSS MGF1 SHA-384 algorithm failed.
 */
#define L8W8JWT_PS384_SIGNATURE_FAILURE 1400

/**
 * Returned if signing a JWT using the RSASSA-PSS MGF1 SHA-512 algorithm failed.
 */
#define L8W8JWT_PS512_SIGNATURE_FAILURE 1500

/**
 * If one of the SHA-2 functions fails (e.g. SHA-256).
 */
#define L8W8JWT_SHA2_FAILURE 1600

/**
 * Returned if some PEM-formatted key string couldn't be parsed.
 */
#define L8W8JWT_KEY_PARSE_FAILURE 1700

/**
 * Base64(URL) encoding or decoding error.
 */
#define L8W8JWT_BASE64_FAILURE 1800

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_RETCODES_H
