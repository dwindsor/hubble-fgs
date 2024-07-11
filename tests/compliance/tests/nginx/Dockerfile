## Helper to clone nginx-tests

FROM alpine/git:2.36.3 AS nginx-tests-clone

WORKDIR /nginx-tests
RUN git clone https://github.com/nginx/nginx-tests .
RUN git checkout master

## Main container image

FROM ubuntu:22.04

RUN apt-get update -y
RUN apt-get install -y libfcgi-perl libio-socket-ssl-perl curl gnupg2 ca-certificates lsb-release ubuntu-keyring

RUN rm -rf /var/lib/apt/lists/*

COPY --from=nginx-tests-clone /nginx-tests /nginx-tests
# FIXME: this test is broken due to bad version string from patched ubuntu package. Get
# rid of it for now.
RUN rm /nginx-tests/h2_server_tokens.t

RUN curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
RUN echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu jammy nginx" > /etc/apt/sources.list.d/nginx.list
RUN apt-get update -y
RUN apt install -y nginx

ENV TEST_NGINX_BINARY=/usr/sbin/nginx
ENV TEST_NGINX_MODULES=/usr/lib/nginx/modules

WORKDIR /nginx-tests
USER nginx

CMD ["sh", "-c", "prove . -v --nocolor"]
