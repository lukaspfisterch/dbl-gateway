# Discovery

dbl-gateway exposes machine-readable discovery surfaces so a client can bootstrap
itself against the execution boundary.

## Surfaces

### `GET /capabilities`

High-level runtime description:

- interface version
- providers and models
- tool surface
- budget surface
- compact surface booleans
- rich `surface_catalog`

### `GET /surfaces`

Explicit catalog of callable surfaces.

Each entry includes:

- `id`
- `path`
- `methods`
- `auth`
- `plane`
- `description`

### `GET /intent-template`

Self-teaching ingress surface.

It returns:

- `target_endpoint`
- `interface_version`
- `template_version`
- `template_schema_digest`
- selected `template`
- example variants

Each template carries an `intent_variant` so tools can distinguish example
profiles without string-parsing the route parameters.

## Bootstrapping Flow

A blind client can start with:

1. `GET /surfaces`
2. `GET /capabilities`
3. `GET /intent-template`
4. `POST /ingress/intent`

That is enough to discover the boundary, learn the envelope, and produce a
valid first interaction.
