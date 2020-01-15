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
 *  @file printferr.h
 *  @author Raphael Beck
 *  @brief printf() structured error messages with these useful macros.
 */

#ifndef L8W8JWT_PRINTFERR_H
#define L8W8JWT_PRINTFERR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/**
 *  Prints a structured error message using <code>printf()</code>.<p>
 *  @param msg The error message to print.
 */
#define l8w8jwt_printferr(msg) printf("\033[0;31m");printf("---\nERROR:\n\ntimestamp:\t%s %s\nsrc file:\t%s:L%d\nfunction:\t%s\nmessage:\t%s\n---\n",__DATE__,__TIME__, __FILE__,__LINE__,__func__,msg);printf("\033[0m")

/**
 *  Prints a structured warning message using <code>printf()</code>.<p>
 *  @param msg The warning message to print.
 */
#define l8w8jwt_printfwrn(msg) printf("\033[0;33m");printf("---\nWARNING:\n\ntimestamp:\t%s %s\nsrc file:\t%s:L%d\nfunction:\t%s\nmessage:\t%s\n---\n",__DATE__,__TIME__, __FILE__,__LINE__,__func__,msg);printf("\033[0m")

#ifdef __cplusplus
} // extern "C"
#endif

#endif // L8W8JWT_PRINTFERR_H
