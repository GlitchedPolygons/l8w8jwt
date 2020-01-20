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
 *  @file hs256.h
 *  @author Raphael Beck
 *  @brief Encode and decode Json Web Tokens using the HMACSHA256 algo.
 */

#ifndef L8W8JWT_HS256_H
#define L8W8JWT_HS256_H

#ifdef __cplusplus
extern "C" {
#endif

#include "l8w8jwt/encode.h"

/**
 * Creates an HS256 signed Json-Web-Token.
 * @param encoding_params Parameters used for token creation containing headers, signing key, output string pointer (where the token will be written into), etc...
 * @return Return code as specified inside retcodes.h
 */
int l8w8jwt_encode_hs256(struct l8w8jwt_encoding_params* encoding_params);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_HS256_H
