# l8w8jwt

[![AppVeyor](https://ci.appveyor.com/api/projects/status/0h3gkursbe2lpnqu?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/l8w8jwt)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/l8w8jwt/tree/master.svg?style=shield)](https://app.circleci.com/github/GlitchedPolygons/l8w8jwt/pipelines?branch=master)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/l8w8jwt/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/l8w8jwt/files.html)

[![Icon](https://github.com/GlitchedPolygons/l8w8jwt/blob/master/icon.png?raw=true)](https://jwt.io/)

### `l8w8jwt` (say "lightweight jawt") is a minimal, OpenSSL-less and super lightweight JWT library written in C. 

Its only significant (in terms of heaviness) dependency is [ARM's open-source MbedTLS library](https://github.com/ARMmbed/mbedtls). 

The others are extremely lightweight header-only libraries for JSON handling and building strings.

> ᐳᐳ  Check out the API docs [here on github.io](https://glitchedpolygons.github.io/l8w8jwt/files.html)

### How to clone

`git clone https://github.com/GlitchedPolygons/l8w8jwt.git`

### How to use

Just add l8w8jwt as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example). 

If you don't want to use git submodules, you can also start vendoring a specific version of l8w8jwt by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

```bash
git submodule add https://github.com/GlitchedPolygons/l8w8jwt.git lib/
git submodule update --init --recursive
```

If you use CMake you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE l8w8jwt)` inside your **CMakeLists.txt** file.



## Examples

### Encoding and signing a token

```C
#include "l8w8jwt/encode.h"

int main(void)
{
    char* jwt;
    size_t jwt_length;

    struct l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);

    params.alg = L8W8JWT_ALG_HS512;

    params.sub = "Gordon Freeman";
    params.iss = "Black Mesa";
    params.aud = "Administrator";

    params.iat = time(NULL);
    params.exp = time(NULL) + 600; /* Set to expire after 10 minutes (600 seconds). */

    params.secret_key = (unsigned char*)"YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
    params.secret_key_length = strlen(params.secret_key);

    params.out = &jwt;
    params.out_length = &jwt_length;

    int r = l8w8jwt_encode(&params);

    printf("\n l8w8jwt example HS512 token: %s \n", r == L8W8JWT_SUCCESS ? jwt : " (encoding failure) ");

    /* Always free the output jwt string! */
    free(jwt);

    return 0;
}
```
---

### Decoding and verifying a token

```C
#include "l8w8jwt/decode.h"

static const char KEY[] = "YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";
static const char JWT[] = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1ODA5MzczMjksImV4cCI6MTU4MDkzNzkyOSwic3ViIjoiR29yZG9uIEZyZWVtYW4iLCJpc3MiOiJCbGFjayBNZXNhIiwiYXVkIjoiQWRtaW5pc3RyYXRvciJ9.7oNEgWxzs4nCtxOgiyTofP2bxZtL8dS7hgGXRPPDmwQWN1pjcwntsyK4Y5Cr9035Ro6Q16WOLiVAbj7k7TeCDA";

int main(void)
{
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_HS512;

    params.jwt = (char*)JWT;
    params.jwt_length = strlen(JWT);

    params.verification_key = (unsigned char*)KEY;
    params.verification_key_length = strlen(KEY);

    /* 
     * Not providing params.validate_iss_length makes it use strlen()
     * Only do this when using properly NUL-terminated C-strings! 
     */
    params.validate_iss = "Black Mesa"; 
    params.validate_sub = "Gordon Freeman";

    /* Expiration validation set to false here only because the above example token is already expired! */
    params.validate_exp = false; 
    params.exp_tolerance_seconds = 60;

    params.validate_iat = true;
    params.iat_tolerance_seconds = 60;

    enum l8w8jwt_validation_result validation_result;

    int decode_result = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

    if (decode_result == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID) 
    {
        printf("\n Example HS512 token validation successful! \n");
    }
    else
    {
        printf("\n Example HS512 token validation failed! \n");
    }
    
    /*
     * decode_results describes whether decoding/parsing the token succeeded or failed;
     * the output l8w8jwt_validation_result variable contains actual information about
     * JWT signature verification status and claims validation (e.g. expiration check).
     */

    return 0;
}
```
