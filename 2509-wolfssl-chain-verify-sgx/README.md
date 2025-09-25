Issue: Compilation fails for enclaved code using wolfSSL.

The `chain_verify.c` code was copied from [../2509-wolfssl-chain-verify](https://github.com/andrade/iamstuck/tree/master/2509-wolfssl-chain-verify) where it works when outside the enclave.

## How to run

First setup the environment (use your own paths):

```shell
$ export SGX_SDK=${HOME}/.local/lib/x86_64-linux-gnu/sgxsdk
$ export WOLFSSL_ROOT=${HOME}/res/gitsaves/wolfssl
$ export SGX_WOLFSSL_LIB=${HOME}/res/gitsaves/wolfssl/IDE/LINUX-SGX

$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$WOLFSSL_ROOT/src/.libs
```

Then generate the SGX signing key (only needs to be done once, clean does not remove the key):

```shell
$ make genkey
```

Then compile with:

```shell
$ make
```

## The compilation errors

```shell
$ make
CURDIR:    /home/daniel/pro/iamstuck/2509-wolfssl-chain-verify-sgx
SGX_SDK:   /home/daniel/.local/lib/x86_64-linux-gnu/sgxsdk
WOLFSSL_ROOT:    /home/daniel/res/gitsaves/wolfssl
SGX_WOLFSSL_LIB: /home/daniel/res/gitsaves/wolfssl/IDE/LINUX-SGX
DEBUG:     ""
------------------------------------------------------------------------
[  GEN   ] enclave.edl  >  enclave_u.c
[  GEN   ] enclave.edl  >  enclave_t.c
[   CC   ] enclave_t.c enclave_t.h  >  enclave_t.o
In file included from /home/daniel/res/gitsaves/wolfssl/wolfssl/ssl.h:33,
                 from enclave_t.h:9,
                 from enclave_t.c:1:
/home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/settings.h:356:6: warning: #warning "No configuration for wolfSSL detected, check header order" [-Wcpp]
  356 |     #warning "No configuration for wolfSSL detected, check header order"
      |      ^~~~~~~
[   CC   ] chain_verify.c km_fixed.h  >  chain_verify.o
In file included from /home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/sp_int.h:405,
                 from /home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/wolfmath.h:51,
                 from /home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/dsa.h:33,
                 from /home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/asn_public.h:36,
                 from /home/daniel/res/gitsaves/wolfssl/wolfssl/ssl.h:36,
                 from chain_verify.c:12:
/home/daniel/res/gitsaves/wolfssl/wolfssl/wolfcrypt/random.h:197:5: error: unknown type name ‘pid_t’
  197 |     pid_t pid;
      |     ^~~~~
In file included from /home/daniel/res/gitsaves/wolfssl/wolfssl/ssl.h:262:
/home/daniel/res/gitsaves/wolfssl/wolfssl/wolfio.h:529:5: error: unknown type name ‘SOCKADDR’
  529 |     SOCKADDR sa;
      |     ^~~~~~~~
/home/daniel/res/gitsaves/wolfssl/wolfssl/wolfio.h:530:5: error: unknown type name ‘SOCKADDR_IN’
  530 |     SOCKADDR_IN sa_in;
      |     ^~~~~~~~~~~
chain_verify.c: In function ‘dump_last_wc_error’:
chain_verify.c:156:15: warning: unused variable ‘error’ [-Wunused-variable]
  156 |         char *error = wolfSSL_ERR_error_string(e, buf);
      |               ^~~~~
make: *** [Makefile:112: chain_verify.o] Error 1
```

Note 1: There were also `error: unknown type name ‘time_t’` errors but these can be worked around by by importing `time.h` (before `ssl.h`):

```C
#include <time.h> // prevent `error: unknown type name ‘time_t’` in ssl.h
#include <wolfssl/ssl.h>
```

Note 2: IIRC the `error: unknown type name ‘pid_t’` didn't appear in wolfSSL 5.8.0 but I could be mistaken. Would have to confirm.

## How I compiled the wolfSSL library

First select the branch `v5.8.2-stable`, and then:

```shell
$ ./autogen.sh && ./configure --prefix=$HOME/.local/lib/x86_64-linux-gnu/wolfssl --enable-static --enable-all --enable-debug && make
```

And for the SGX part:

```shell
$ make -f sgx_t_static.mk CFLAGS="-DDEBUG_WOLFSSL -DWOLFSSL_PUB_PEM_TO_DER" HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_TEST=1 HAVE_WOLFSSL_SP=1
```
