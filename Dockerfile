#ARG LIST
ARG NGINX_VERSION=1.27.4
ARG NGINX_COMMIT=ecb809305e54ed15be9f620d56b19ff4e4be7db5
ARG OPENSSL_VERSION=3.5.0
ARG PCRE_VERSION=10.45
ARG GEOIP2_VERSION=3.4
ARG ZSTD_VERSION=0.1.1
ARG HEADERS_MORE_VERSION=0.38
ARG NGX_BROTLI_COMMIT=a71f9312c2deb28875acc7bacfdd5695a111aa53
ARG NJS_COMMIT=9d3e71ca656b920e3e63b0e647aca8e91669d29a
ARG ZLIB_URL=https://github.com/cloudflare/zlib.git
ARG ZLIB_COMMIT=1252e2565573fe150897c9d8b44d3453396575ff
ARG NGINX_USER_UID=100
ARG NGINX_GROUP_GID=101
ARG CONFIG="\
             --prefix=/etc/nginx \
             --sbin-path=/usr/sbin/nginx \
             --conf-path=/etc/nginx/nginx.conf \
             --error-log-path=/var/log/nginx/error.log \
             --http-log-path=/var/log/nginx/access.log \
             --pid-path=/var/run/nginx/nginx.pid \
             --lock-path=/var/run/nginx/nginx.lock \
             --http-client-body-temp-path=/var/cache/nginx/client_temp \
             --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
             --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
             --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
             --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
             --user=nginx \
             --group=nginx \
             --with-http_ssl_module \
             --with-http_realip_module \
             --with-http_addition_module \
             --with-http_sub_module \
             --with-http_dav_module \
             --with-http_flv_module \
             --with-http_mp4_module \
             --with-http_gunzip_module \
             --with-http_gzip_static_module \
             --with-http_random_index_module \
             --with-http_secure_link_module \
             --with-http_stub_status_module \
             --with-http_auth_request_module \
             --with-http_xslt_module=dynamic \
             --with-http_image_filter_module=dynamic \
             --with-http_geoip_module=dynamic \
             --with-http_perl_module=dynamic \
             --with-threads \
             --with-stream \
             --with-stream_ssl_module \
             --with-stream_ssl_preread_module \
             --with-stream_realip_module \
             --with-stream_geoip_module=dynamic \
             --with-http_slice_module \
             --with-mail \
             --with-mail_ssl_module \
             --with-compat \
             --with-file-aio \
             --with-http_v2_module \
             --with-http_v3_module \
             --with-openssl=/build/openssl-${OPENSSL_VERSION} \
             --with-openssl-opt="${OPENSSL_OPT}" \
             --with-pcre-jit \
             --with-pcre=/build/pcre2-${PCRE_VERSION} \
             --with-zlib=/build/zlib \
             --add-module=/build/ngx_brotli \
             --add-module=/build/headers-more-nginx-module-${HEADERS_MORE_VERSION} \
             --add-module=/build/njs/nginx \
             --add-module=/build/zstd \
             --add-dynamic-module=/build/ngx_http_geoip2_module \
"




# Stage 1: Builder
FROM alpine:3.21.3 AS base

ARG NGINX_VERSION
ARG NGINX_COMMIT
ARG OPENSSL_VERSION
ARG PCRE_VERSION
ARG GEOIP2_VERSION
ARG ZSTD_VERSION
ARG HEADERS_MORE_VERSION
ARG NGX_BROTLI_COMMIT
ARG NJS_COMMIT
ARG ZLIB_URL
ARG ZLIB_COMMIT
ARG NGINX_USER_UID
ARG NGINX_GROUP_GID
ARG CONFIG

# Install build dependencies
RUN NB_PROC=$(grep -c ^processor /proc/cpuinfo) && \
    apk update && \
    apk upgrade --no-cache -a && \
    apk add --no-cache --virtual .build-deps \
		gcc \
		gd-dev \
		geoip-dev \
		gnupg \
		go \
		libc-dev \
		libxslt-dev \
		linux-headers \
		make \
		mercurial \
		musl-dev \
		ninja \
		openssl-dev \
		pcre-dev \
		perl-dev \
    patch \
		zlib-dev && \
	  apk add --no-cache --virtual .brotli-build-deps \
		autoconf \
		automake \
		cmake \
		g++ \
		git \
		libtool && \
	  apk add --no-cache --virtual .geoip2-build-deps \
		libmaxminddb-dev && \
	  apk add --no-cache --virtual .njs-build-deps \
		libedit-dev \
		libxml2-dev \
		libxslt-dev \
		openssl-dev \
		pcre-dev \
		readline-dev \
		zlib-dev && \
	  apk add --no-cache --virtual .zstd-build-deps \
		zstd-dev 

WORKDIR /build

# Build dependencies dengan optimasi multi-arch
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
    "amd64") ARCH_FLAGS="-march=x86-64-v3" ;; \
    "arm64") ARCH_FLAGS="-march=armv8-a" ;; \
    *) ARCH_FLAGS="" ;; \
    esac && \
    export CFLAGS="${CFLAGS} ${ARCH_FLAGS}"


# Download sources and configure nginx module and some component for building nginx custom
RUN \
  wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -O - | tar zxf - -C /build && \
  wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz -O - | tar xzf - -C /build && \
  wget -q https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE_VERSION}/pcre2-${PCRE_VERSION}.tar.gz -O - | tar xzf - -C /build && \
  git clone --depth 1 ${ZLIB_URL} /build/zlib && \
  cd /build/zlib && \
  git fetch --depth 1 origin ${ZLIB_COMMIT} && \
  git checkout -q FETCH_HEAD && \
  ./configure && \
  git clone --depth 1 https://github.com/google/ngx_brotli.git /build/ngx_brotli && \
  cd /build/ngx_brotli && \
	git fetch --depth 1 origin $NGX_BROTLI_COMMIT && \
	git checkout --recurse-submodules -q FETCH_HEAD && \
	git submodule update --init --depth 1 && \
  cd /build && \
  git clone --depth 1 --branch ${GEOIP2_VERSION} https://github.com/leev/ngx_http_geoip2_module.git /build/ngx_http_geoip2_module && \
  git clone --depth 1 --branch ${ZSTD_VERSION} https://github.com/tokers/zstd-nginx-module.git /build/zstd && \
  wget -q https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz -O - | tar xzf  - -C /build && \
  git clone https://github.com/bellard/quickjs && \
  cd quickjs && \
  make -j$(nproc) && \
  echo "quickjs $(cat VERSION)" && \
  cd /build && \
  git clone --depth 1 https://github.com/nginx/njs.git && \
  cd njs && \
  git fetch --depth 1 origin ${NJS_COMMIT} && \
  git checkout -q FETCH_HEAD && \
  ./configure \
  --cc-opt='-I /build/quickjs' \
  --ld-opt='-L /build/quickjs' && \
  make -j$(nproc) && \
  mv build/njs/ /usr/local/bin/

# Apply security patches
RUN git clone --depth 1 https://github.com/jauderho/patches.git && \
    cd nginx-${NGINX_VERSION} && \
    patch -p1 < ../patches/nginx/nginx__dynamic_tls_records_1.27.2+.patch && \
    patch -p1 < ../patches/nginx/nginx-1.25.3-reprioritize-chacha-openssl-1.1.1.patch && \
    patch -p1 < ../patches/nginx/nginx-gzip-207-status.patch


# Configure and build NGINX
ARG CC_OPT='-fuse-ld=mold -O3 -march=native -pipe -flto -ffat-lto-objects -fstack-protector-strong -fexceptions --param=ssp-buffer-size=4 -grecord-gcc-switches -pie -fno-semantic-interposition -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wformat-security -Wno-error=strict-aliasing -Wextra -Wp,-D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -I /build/quickjs'
ARG LD_OPT='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -pie -L /build/quickjs'
ARG OPENSSL_OPT="enable-ec_nistp_64_gcc_128 threads no-ssl no-tls1 no-tls1_1 no-weak-ssl-ciphers no-tests"



RUN mkdir -p /var/run/nginx/ && \
    cd /build/nginx-${NGINX_VERSION} && \
    ./configure $CONFIG && \
    PATH="/usr/lib/ccache:${PATH}" make -j $NB_PROC && \
    ccache -s && \
    strip objs/nginx && \
    make install && \
    rm -rf /etc/nginx/html/ && \
    mkdir /etc/nginx/conf.d/ && \
    wget -q https://ssl-config.mozilla.org/ffdhe2048.txt -O /etc/ssl/dhparam.pem && \
    apk del .build-deps && \
    rm -rf /var/cache/apk/* /tmp/* /build/*

# Stage 2: Runtime
FROM alpine:3.21.3

ARG NGINX_VERSION
ARG NGINX_COMMIT
ARG NGINX_USER_UID
ARG NGINX_GROUP_GID

ENV NGINX_VERSION=$NGINX_VERSION
ENV NGINX_COMMIT=$NGINX_COMMIT

COPY --from=base /var/run/nginx/ /var/run/nginx/
COPY --from=base /etc/nginx /etc/nginx
COPY --from=base /usr/lib/nginx/modules/*.so /usr/lib/nginx/modules/
COPY --from=base /usr/sbin/nginx /usr/sbin/
COPY --from=base /usr/local/lib/perl5/site_perl /usr/local/lib/perl5/site_perl
COPY --from=base /usr/bin/envsubst /usr/local/bin/envsubst
COPY --from=base /etc/ssl/dhparam.pem /etc/ssl/dhparam.pem

COPY --from=base /usr/sbin/njs /usr/sbin/njs

RUN \
    addgroup -S -g $NGINX_GROUP_GID nginx && \
    adduser -S -D -H -u $NGINX_USER_UID -G nginx -s /sbin/nologin -h /var/cache/nginx nginx && \
    ln -s /usr/lib/nginx/modules /etc/nginx/modules && \
    mkdir -p /var/log/nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx /var/cache/nginx

COPY nginx.conf /etc/nginx/nginx.conf
COPY ssl_common.conf /etc/nginx/conf.d/ssl_common.conf

# show env
RUN env | sort

# njs version
RUN njs -v

# test the configuration
RUN nginx -V; nginx -t



HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost/ || exit 1

EXPOSE 80 443
STOPSIGNAL SIGTERM

RUN \
  chown -R --verbose nginx:nginx \
    /var/run/nginx/

USER nginx
CMD ["nginx", "-g", "daemon off;"]
