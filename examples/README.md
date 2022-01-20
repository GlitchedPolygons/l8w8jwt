# How to generate keys that can be used in l8w8jwt

## Using OpenSSL

Even though l8w8jwt itself does not use the OpenSSL library in any way, you may still use the OpenSSL CLI to generate key pairs that you can then use in l8w8jwt.

Here's a list of OpenSSL CLI commands to use for generating key pairs that are PEM-formatted and ready for usage within `l8w8jwt`:

* ES256
* * `openssl ecparam -name prime256v1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem`

* ES384
* * `openssl ecparam -name secp384r1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem`

* ES512
* * `openssl ecparam -name secp521r1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem`

* ES256K
* * `openssl ecparam -name secp256k1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem`

* RS256, RS384, RS512, PS256, PS384, PS512
* * `openssl genrsa -out private.pem 4096 && openssl rsa -in private.pem -outform PEM -pubout -out public.pem`

All of the above commands will generate two files in the current working directory that your shell is in: `private.pem` and `public.pem`. These files contain the generated private and public key respectively, both PEM-formatted.
