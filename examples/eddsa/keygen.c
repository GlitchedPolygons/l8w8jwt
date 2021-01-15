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

#include <stdio.h>
#include <string.h>
#include "../../lib/ed25519/src/sha512.h"
#include "../../lib/ed25519/src/ed25519.h"

/*
 * This example CLI program can be called without any arguments,
 * or with an unlimited amount of arguments where every argument
 * is added as custom, user-provided additional entropy to use for key generation.
 */

int main(int argc, char* argv[])
{
#if L8W8JWT_ENABLE_EDDSA
    unsigned char seed[32] = { 0x00 };
    ed25519_create_seed(seed);

    unsigned char public_key[32] = { 0x00 };
    unsigned char private_key[64] = { 0x00 };

    // Collect additional custom user-provided entropy from the CLI arguments.
    if (argc > 1)
    {
        unsigned char md[64];
        sha512_context sha512;
        sha512_init(&sha512);
        for (int i = 0; i < argc; ++i)
        {
            const char* s = argv[i];
            sha512_update(&sha512, (const unsigned char*)s, strlen(s));
        }
        sha512_final(&sha512, md);
        for (int i = 0; i < 64; ++i)
        {
            seed[i % 16] *= md[i];
        }
    }

    ed25519_create_keypair_ref10(public_key, private_key, seed);

    // Print it out as a hex-encoded string:

    printf("\n---\nEd25519 Key Generation\n---\n\nPublic Key:\n");
    for (int i = 0; i < sizeof(public_key); ++i)
    {
        printf("%02x", public_key[i]);
    }
    printf("\n\n---\n\nPrivate Key:   (Ref10-format)\n");
    for (int i = 0; i < sizeof(private_key); ++i)
    {
        printf("%02x", private_key[i]);
    }
    printf("\n\n---\n");
#else
    printf("\nEdDSA not supported here - please build l8w8jwt with \"L8W8JWT_ENABLE_EDDSA\" set to 1\n");
#endif
}