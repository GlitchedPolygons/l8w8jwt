# l8w8jwt

[![Codacy](https://api.codacy.com/project/badge/Grade/28a58c3e4240456892dec1bd8895d5b6)](https://www.codacy.com/manual/GlitchedPolygons/l8w8jwt?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/l8w8jwt&amp;utm_campaign=Badge_Grade)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/l8w8jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/l8w8jwt)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/0h3gkursbe2lpnqu?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/l8w8jwt)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/l8w8jwt/tree/master.svg?style=shield)](https://app.circleci.com/github/GlitchedPolygons/l8w8jwt/pipelines?branch=master)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/l8w8jwt/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/l8w8jwt/files.html)

[![Icon](https://github.com/GlitchedPolygons/l8w8jwt/blob/master/icon.png?raw=true)](https://jwt.io/)

### `l8w8jwt` (say "lightweight jawt") is a minimal, OpenSSL-less and super lightweight JWT library written in C. 

Its only significant dependency (in terms of heaviness) is [ARM's open-source MbedTLS library](https://github.com/ARMmbed/mbedtls). 

The others are extremely lightweight header-only libraries for JSON handling and building strings.

> ᐳᐳ  Check out the API docs [here on github.io](https://glitchedpolygons.github.io/l8w8jwt/files.html)

### How to clone

`git clone https://github.com/GlitchedPolygons/l8w8jwt.git`

### How to use

Just add l8w8jwt as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example). 

```
git submodule add https://github.com/GlitchedPolygons/l8w8jwt.git lib/
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of l8w8jwt by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

### Linking 

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

**More examples can be found inside this repo's [`examples/`](https://github.com/GlitchedPolygons/l8w8jwt/tree/master/examples) folder - check them out now and find out how to encode/decode custom claims and sign using the various asymmetric algos!**

### Mandatory parameters

Some encoding/decoding parameters can be omitted, while others can't. 

Here is the overview of minimal **required** parameters that can't be omitted for encoding and decoding JWTs:

<details>
<summary>
<strong>Encode</strong>
</summary>
<ul>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__encoding__params.html#a5bf39d6b8874a581a6787b9784403c44">l8w8jwt_encoding_params.alg</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__encoding__params.html#a34152cd49b4ea1bd906672b8167556d8">l8w8jwt_encoding_params.secret_key</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__encoding__params.html#a76e20b9285d52accb63ac5fc1dc924f7">l8w8jwt_encoding_params.secret_key_length</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__encoding__params.html#aff53956be385bd146899b80c44ae9484">l8w8jwt_encoding_params.out</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__encoding__params.html#a06c545ea2dd26dbcd3a8a7182c85b745">l8w8jwt_encoding_params.out_length</a></li>
</ul>
</details>

<details>
<summary>
<strong>Decode</strong>
</summary>
<ul>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__decoding__params.html#a8cbaab2006eac325b92c1874020bcb1a">l8w8jwt_decoding_params.alg</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__decoding__params.html#a5fdb41e8f132385efd054f82c5e8b3d9">l8w8jwt_encoding_params.jwt</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__decoding__params.html#a75ba9b9c4dc7bd55b8e058f45fe8b66f">l8w8jwt_encoding_params.jwt_length</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__decoding__params.html#af3a727dbda6d1a1b06934249a86b05c5">l8w8jwt_encoding_params.verification_key</a></li>
    <li><a href="https://glitchedpolygons.github.io/l8w8jwt/structl8w8jwt__decoding__params.html#aeafb73bb540cf91f61dbda889a470d96">l8w8jwt_encoding_params.verification_key_length</a></li>
</ul>
</details>
