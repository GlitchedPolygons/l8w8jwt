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

#include "l8w8jwt/hs256.h"
#include "l8w8jwt/base64.h"

#include <stdio.h>
#include <string.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

int l8w8jwt_encode_hs256()
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = &mbedtls_sha256_info;

    unsigned char tmp[32];
    int r = mbedtls_md_hmac(&mbedtls_sha256_info, "test", 4, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0", 56, tmp);

    printf("\n%s", tmp);

    size_t tmp2;
    printf("\n%s", l8w8jwt_base64_encode(true, tmp, 32, &tmp2));

    unsigned char* ss = l8w8jwt_base64_decode(true, "Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY", strlen("Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY"), &tmp2);
    printf("\n%s", ss);

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
