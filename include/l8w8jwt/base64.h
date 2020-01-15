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
 *  @file base64.h
 *  @author Raphael Beck
 *  @brief Base-64 encode and decode strings/bytes. <p>
 *  @warning The caller is responsible for freeing the returned buffers!
 */

#ifndef L8W8JWT_BASE64_H
#define L8W8JWT_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

/**
 *  Encodes a byte array to a base-64 string. <p>
 *  If you're encoding a string, don't include the nul terminator
 *  (pass <code>strlen(data)</code> instead of the array's size to the <code>data_length</code> parameter). <p>
 *
 *  @note The returned buffer is nul terminated to make it easier to use as a C string.
 *  @note The nul terminator is NOT included in the <code>out_length</code>.
 *  @note DO NOT forget to call <code>free()</code> on the returned buffer once you're done using it!
 *
 *  @param data The data (array of bytes) to base-64 encode.
 *  @param data_length The length of the input data array (in case of a C string: array size - 1 in order to omit the nul terminator).
 *  @param out_length Pointer to a <code>size_t</code> variable containing the length of the output buffer minus the nul terminator.
 *
 *  @return Base-64 encoded string, or <code>NULL</code> in case of a failure (errors are <code>printf</code>'ed).
 */
char* l8w8jwt_base64_encode(const uint8_t* data, size_t data_length, size_t* out_length);

/**
 *  Decodes a base-64 encoded string to an array of bytes. <p>
 *
 *  @note The returned bytes buffer is nul terminated to allow usage as a C string.
 *  @note The nul terminator is NOT included in the <code>out_length</code>.
 *  @note DO NOT forget to call <code>free()</code> on the returned buffer once you're done using it!
 *
 *  @param data The base-64 encoded string to decode (obtained via {@link base64_encode}).
 *  @param data_length The length of the string to decode.
 *  @param out_length Pointer to a <code>size_t</code> variable into which to write the output buffer's length.
 *
 *  @return The decoded bytes; <code>NULL</code> in case of a failure (errors are <code>printf</code>'ed).
 */
uint8_t* l8w8jwt_base64_decode(const char* data, size_t data_length, size_t* out_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_BASE64_H
