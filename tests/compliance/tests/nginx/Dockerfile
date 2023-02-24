## Helper to clone nginx-tests

FROM alpine/git:2.36.3 as nginx-tests-clone

WORKDIR /nginx-tests
RUN git clone https://github.com/nginx/nginx-tests .
RUN git checkout 64a9195a31680c54ae5a4b71194ca9bb7f186875

## Main container image

FROM ubuntu:22.10

RUN apt-get update -y
RUN apt-get install -y nginx nginx-extras libfcgi-perl

RUN rm -rf /var/lib/apt/lists/*

COPY --from=nginx-tests-clone /nginx-tests /nginx-tests
# FIXME: this test is broken due to bad version string from patched ubuntu package. Get
# rid of it for now.
RUN rm /nginx-tests/h2_server_tokens.t
# These tests don't currently work due to bugs in their TAP output.
RUN rm /nginx-tests/js_fetch_https.t
RUN rm /nginx-tests/js_fetch_verify.t

ENV TEST_NGINX_BINARY=/usr/sbin/nginx
ENV TEST_NGINX_MODULES=/usr/lib/nginx/modules

RUN useradd -ms /bin/sh nginx

WORKDIR /nginx-tests
USER nginx

CMD ["sh", "-c", "prove ."]
