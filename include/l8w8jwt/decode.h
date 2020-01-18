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
 *  @brief Core decode function for l8w8jwt. Use this to decode, then verify using the specific implementation (e.g. HS256, etc...)!
 */

#ifndef L8W8JWT_DECODE_H
#define L8W8JWT_DECODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "l8w8jwt/claim.h"
#include "l8w8jwt/retcodes.h"

    // TODO: write the decode function!
int l8w8jwt_decode();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_DECODE_H
