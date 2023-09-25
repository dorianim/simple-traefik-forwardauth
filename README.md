# simple-traefik-forwardauth
OpenID connect [Traefik forward authentication](https://doc.traefik.io/traefik/middlewares/http/forwardauth) provider. As simple as it can be.

`docker-compose.yml` configuration example:
```yaml
version: "3"
services:
  traefik:
    image: docker.io/library/traefik:v2.10
    command: --api.insecure=true --providers.docker --entrypoints.web.address=:80
    ports:
      - 8080:80
    volumes:
      #- ./config:/etc/traefik
      - /var/run/docker.sock:/var/run/docker.sock
    labels:
      traefik.enable: true
      traefik.http.routers.dashboard.rule: Host(`dash.localhost`)
      traefik.http.routers.dashboard.service: api@internal
      traefik.http.routers.dashboard.entrypoints: web

  whoami:
    image: docker.io/traefik/whoami
    labels:
      traefik.enable: true
      traefik.http.routers.whoami.rule: Host(`localhost`)
      traefik.http.routers.whoami.entrypoints: web
      traefik.http.routers.whoami.middlewares: simple-forwardauth

  simple-forwardauth:
    image: ghcr.io/dorianim/simple-traefik-forwardauth
    environment:
      # generate with `hexdump -vn64 -e'16/4 "%08X" 1 "\n"' /dev/random`
      SECRET_KEY=4F9H...
      OIDC_ISSUER_URL=https://kecloak.example.com/realms/example
      OIDC_CLIENT_ID=example
      OIDC_CLIENT_SECRET=super-secret
      #PATH_FILTER_REGEX='/test'
      #PATH_FILTER_STRATEGY=Blacklist
    labels:
      traefik.enable: true
      traefik.http.middlewares.simple-forwardauth.forwardauth.address: http://simple-forwardauth:3759
      traefik.http.middlewares.simple-forwardauth.forwardauth.authResponseHeaders: x-forwarded-username,x-forwarded-name,x-forwarded-email
```

## Config options

- `SECRET_KEY` (**required**): 64-bit random key encoded in hex. Generate with `hexdump -vn64 -e'16/4 "%08X" 1 "\n"' /dev/random`
- `OIDC_ISSUER_URL` (**required**): issuer URL of your identity provider
- `OIDC_CLIENT_ID` (**required**): ID of your client
- `OIDC_CLIENT_SECRET` (**required**): secret of your client
- `OIDC_SCOPES`: scopes to request, defaults to `profile,email`
- `PATH_FILTER_REGEX`: a regex to filter pathts to black/white list, defaults to empty
- `PATH_FILTER_STRATEGY`: can be `Blacklist` or `Whitelist`, defaults to `Whitelist`

## Note

I don't have a lot of spare time to maintain this project, so I'm really trying to keep this as simple as possible. 
Therefore, I don't have much of a desire to add any features, unless there is a really good reason to.
But if you find any bugs, feel free to open an issue or pull request.