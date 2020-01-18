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

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_RETCODES_H
