# The Problem

Issue: Code runs all good (returns all zeros) with the wolfSSL version in Ubuntu 24.04's repositories (5.6.6-1.3build1). But the output changes unexpectedly when using wolfSSL 5.8.2.

I've compiled the library twice, with `v5.6.6-stable` (to mirror Ubuntu's version) and with `v5.8.2-stable`, to confirm the issue.

Note the errors thrown when using v5.8.2, fails right away when loading the first certificate. (I've confirmed both certificate chain and signature are valid using OpenSSL.)

## How to run

First setup the environment (use your own paths):

```shell
$ export WOLFSSL_ROOT=${HOME}/res/gitsaves/wolfssl
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$WOLFSSL_ROOT/src/.libs
```

Then compile and run with `v5.6.6-stable` (OK):

```shell
$ gcc -g -Wall -Wextra -I $WOLFSSL_ROOT -L $WOLFSSL_ROOT/src/.libs/ -o chain_verify chain_verify.c -l wolfssl

$ ./chain_verify
validate_cert_chain, r = 0
compute_hash, r = 0
get_rsa_pubkey_from_pem_cert, r = 0
verify_signature, r = 0

$ ldd chain_verify
(...)
libwolfssl.so.42 => /home/daniel/res/gitsaves/wolfssl/src/.libs/libwolfssl.so.42 (0x0000765e0dc00000)
(...)
```

Or compile and run with `v5.8.2-stable` (Fails):

```shell
$ gcc -g -Wall -Wextra -I $WOLFSSL_ROOT -L $WOLFSSL_ROOT/src/.libs/ -o chain_verify chain_verify.c -l wolfssl

$ ./chain_verify
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 23488 ASN_PARSE_E (-140)
Failure: wolfSSL_X509_load_certificate_buffer
wolfSSL last error: ASN parsing error, invalid input (140)
validate_cert_chain, r = 1
compute_hash, r = 0
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 23488 ASN_PARSE_E (-140)
Failure: wc_ParseCert
get_rsa_pubkey_from_pem_cert, r = 2
Failure: get_rsa_pubkey_from_pem_cert
verify_signature, r = 2

$ ldd chain_verify
(...)
libwolfssl.so.44 => /home/daniel/res/gitsaves/wolfssl/src/.libs/libwolfssl.so.44 (0x000079ca90e00000)
(...)
```

## How I compiled the wolfSSL library

First select the branch `v5.6.6-stable` or `v5.8.2-stable`, and then:

```shell
$ ./autogen.sh
$ ./configure --prefix=$HOME/.local/lib/x86_64-linux-gnu/wolfssl --enable-static --enable-all --enable-debug --enable-debug-code-points --enable-debug-trace-errcodes
$ make
```

# Fixing the Problem

Got help [here](https://www.wolfssl.com/forums/topic2388-code-runs-successfully-in-v566stable-but-fails-in-v582stable.html). There was a change in wolfSSL to disallow certificates with serial numbers set to zero.

This seems in line with [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2):

> The serial number MUST be a positive integer assigned by the CA to each certificate.

## Workaround

To use certificates with serial numbers of zero, can compile wolfSSL with the flag `CFLAGS='-DWOLFSSL_ASN_ALLOW_0_SERIAL'`:

```shell
$ CFLAGS='-DWOLFSSL_ASN_ALLOW_0_SERIAL' ./configure --prefix=$HOME/.local/lib/x86_64-linux-gnu/wolfssl --enable-static --enable-all --enable-debug --enable-debug-code-points --enable-debug-trace-errcodes
```

## Avoiding the problem

Instead of ignoring the problem, better to avoid it entirely by using certificates with serial numbers >0. (In this case, the flag above is not needed.)

The header `km_fixed.h` contains certificates with positive serial numbers. Use it instead of `km.h` in `chain_verify.c`.

Output (without the flag and with certs having positive serial numbers):

```shell
$ ./chain_verify
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1279 ASN_PARSE_E (-140)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1279 ASN_PARSE_E (-140)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1279 ASN_PARSE_E (-140)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: ./src/x509_str.c L 1057 WOLFSSL_FAILURE (0)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
ERR TRACE: wolfcrypt/src/asn.c L 1279 ASN_PARSE_E (-140)
validate_cert_chain, r = 0
compute_hash, r = 0
ERR TRACE: wolfcrypt/src/asn.c L 1628 ASN_OBJECT_ID_E (-144)
get_rsa_pubkey_from_pem_cert, r = 0
verify_signature, r = 0
```

There are still error traces but the output is correct. Recompiling wolfSSL without `--enable-debug-code-points --enable-debug-trace-errcodes` removes these traces:

```shell
$ ./chain_verify
validate_cert_chain, r = 0
compute_hash, r = 0
get_rsa_pubkey_from_pem_cert, r = 0
verify_signature, r = 0
```
