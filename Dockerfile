FROM rust:1.83-alpine as build

WORKDIR /build
COPY . .
ENV RUSTFLAGS='-C target-feature=+crt-static' 

RUN apk add --no-cache build-base pkgconfig openssl-dev ca-certificates
RUN echo $(rustup show | head -n 1 | awk '{print $NF}') > /platform
RUN cargo build --release --target $(cat /platform) --bin simple-traefik-forwardauth
RUN mv target/$(cat /platform)/release/simple-traefik-forwardauth simple-traefik-forwardauth

FROM scratch
COPY --from=build \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/certs/ca-certificates.crt
COPY --from=build /build/simple-traefik-forwardauth /simple-traefik-forwardauth
EXPOSE 3759
ENTRYPOINT ["/simple-traefik-forwardauth"]