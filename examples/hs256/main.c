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

#include "l8w8jwt/hs256.h"
#include <string.h>

int main(void)
{
    char* jwt;
    size_t jwt_length;

    struct l8w8jwt_encoding_params params = {
            .sub = "Gordon Freeman",
            .sub_length = strlen("Gordon Freeman"),
            .iss = "Black Mesa",
            .iss_length = strlen("Black Mesa"),
            .iat = time(NULL),
            .exp = time(NULL) + 600,
            .secret_key = (unsigned char*)"test key",
            .secret_key_length = 8,
            .out = &jwt,
            .out_length = &jwt_length
    };

    l8w8jwt_encode_hs256(&params);

    return 0;
}