# What is this?

This docker image contains curl that's linked against openssl 3.0 with ktls enabled.
To use it:

    docker run -it quay.io/isovalent-dev/ktls-curl:latest bash
    curl https://google.com

# How do you know it's using ktls?

There are a couple of things you can verify.

## 1. Check shared library dependencies

Make sure `curl` depends on openssl library under `/openssl/lib64`:

    # ldd /usr/local/bin/curl | grep ssl
            libssl.so.3 => /openssl/lib64/libssl.so.3 (0x00007f1d2b155000)
            libcrypto.so.3 => /openssl/lib64/libcrypto.so.3 (0x00007f1d2ace2000)

# 2. Check curl version

Run `curl version` and verify that `OpenSSL` version is `3.0.0`:

    # /usr/local/bin/curl --version
    curl 7.79.1 (x86_64-pc-linux-gnu) libcurl/7.79.1 OpenSSL/3.0.0

# 3. Run strace and check socket options

You should see `setsockopt` with `TLS_TX` flag

    # strace /usr/local/bin/curl https://google.com 2>&1 | grep SOL_TLS
    setsockopt(5, SOL_TLS, TLS_TX, "..."..., 56) = -1 ENOPROTOOPT (Protocol not available)

If it returns `ENOPROTOOPT`, it means the kernel is not configured properly to use ktls.
Consult John.
