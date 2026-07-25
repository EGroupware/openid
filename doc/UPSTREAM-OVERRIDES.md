# Upstream overrides audit

Catalog of every `src/` class that forks, patches or extends upstream code (as opposed to
EGroupware-specific storage/UI integration), why it exists, and what should happen to it once
the app is rebased on current upstream releases (see the feature-branch rewrite plan). Vendored
versions at time of writing: `league/oauth2-server` 7.4.0, `steverhoades/oauth2-openid-connect-server`
1.3.0, `lcobucci/jwt` 3.4.6, `slim/slim` 3.13.0.

## (a) EGroupware integration code (not an override - keep as-is)

The storage layer: `Repositories/{Client,AccessToken,AuthCode,RefreshToken,Scope,User,Identity,Grant,Base}.php`,
`Entities/{Client,AccessToken,AuthCode,RefreshToken,Scope,User}Entity.php` (+ `Entities/Traits/*`).
Plus `Keys.php`, `Authorize.php`, `Hooks.php`, `Log/*`, `Ui.php`, `User.php`, `Token.php`,
`AdminCmds/Client.php`. These implement upstream *interfaces* (see table below) but contain no
copied upstream logic - they are pure EGroupware integration and should be reused unchanged,
adapting only to interface signature changes forced by the new league/oauth2-server version.

| File | Interface(s) implemented |
|---|---|
| `Repositories/ClientRepository.php` | `ClientRepositoryInterface` |
| `Repositories/AccessTokenRepository.php` | `AccessTokenRepositoryInterface` |
| `Repositories/AuthCodeRepository.php` | `AuthCodeRepositoryInterface` |
| `Repositories/RefreshTokenRepository.php` | `RefreshTokenRepositoryInterface` |
| `Repositories/ScopeRepository.php` | `ScopeRepositoryInterface` |
| `Repositories/UserRepository.php` | `UserRepositoryInterface` |
| `Repositories/IdentityRepository.php` | `IdentityProviderInterface` (steverhoades) |
| `Entities/ClientEntity.php` | `ClientEntityInterface` |
| `Entities/AccessTokenEntity.php` | `AccessTokenEntityInterface` |
| `Entities/AuthCodeEntity.php` | `AuthCodeEntityInterface` |
| `Entities/RefreshTokenEntity.php` | `RefreshTokenEntityInterface` |
| `Entities/ScopeEntity.php` | `ScopeEntityInterface` |
| `Entities/UserEntity.php` | `UserEntityInterface`, `ClaimSetInterface` (steverhoades) |

DB tables backing this layer (untouched by the rewrite): `egw_openid_scopes`, `egw_openid_clients`,
`egw_openid_client_scopes`, `egw_openid_client_grants`, `egw_openid_user_grants`,
`egw_openid_user_scopes`, `egw_openid_user_clients`, `egw_openid_access_tokens`,
`egw_openid_access_token_scopes`, `egw_openid_refresh_tokens`, `egw_openid_auth_codes`,
`egw_openid_auth_code_scopes`.

## (b) Forked/patched upstream classes ("overwrites")

These re-implement (not just extend) an upstream class because a bug needed fixing or a feature
was missing upstream. Each needs to be re-derived against the new upstream API surface, not
copy-pasted forward as-is.

- **`AuthorizationServer.php`** - forks `League\OAuth2\Server\AuthorizationServer` for two things:
  (1) client-specific access-token TTL (`respondToAccessTokenRequest` looks up
  `ClientRepository::getDefault*TTL()` per-client instead of one global TTL), (2) RFC7662 token
  introspection support (`validateIntrospectionRequest`/`respondToIntrospectionRequest`), based on
  the still-unmerged league PR #925 (confirmed still open/closed-unmerged upstream, and there's no
  native introspection even in league v9.4 - issue #1473 tracks this). Both responsibilities must
  survive the rewrite.
- **`Grant/ImplicitGrant.php`** - full copy of league's `ImplicitGrant`, patched so
  `canRespondToAuthorizationRequest()`/`validateAuthorizationRequest()` accept space-separated
  `response_type` values containing `token`, `id_token` and/or `code` (hybrid flow), not just
  `token` - needed for Guacamole and general OIDC hybrid-flow clients. League has never added this
  upstream (it's OIDC-specific, out of scope for a pure OAuth2 library).
  **Finding:** `Grant/PasswordGrant.php`/`Grant/RefreshTokenGrant.php` do NOT actually add nonce or
  id_token logic themselves - they exist purely because `Grant/Traits/GetClientTrait.php` needed a
  public `getClient()` (league's `validateClient()` is `protected`), for the client-TTL feature in
  `AuthorizationServer.php`. When rebasing, check whether v9's own visibility already makes this
  trait unnecessary before re-porting it.
- **`Grant/AuthCodeGrant.php`** - extends (not forks) `League\OAuth2\Server\Grant\AuthCodeGrant` to
  persist the request's `nonce` against the issued auth code and add it as an `id_token` claim on
  token exchange (OpenID Connect spec requirement; fixed Moodle's `auth_oidc` plugin). League has
  no native OIDC nonce handling - keep this override.
- **`ResponseTypes/IdTokenResponse.php`** - extends steverhoades' `BaseIdTokenResponse` for: (1)
  using `X-Forwarded-Host` instead of `Host` when computing the issuer (fixes JWT validation behind
  a reverse proxy), (2) adding the `nonce` claim, (3) PHP8/`DateTimeImmutable` and nullable-param
  fixes that are artifacts of the PHP8 compatibility push and become moot once rebased on a
  current, PHP8-native steverhoades release - only the X-Forwarded-Host and nonce logic need to
  carry forward.
- **`ClaimExtractor.php`** - extends steverhoades' `ClaimExtractor` to register three
  EGroupware-only claim sets: `roles` (user/admin), `groups` (group names), `email_aliases` (all
  known addresses for the user). No upstream equivalent; keep.
- **`RequestTypes/AuthorizationRequest.php`** - extends steverhoades' request type to persist the
  `response_type` parameter and hold a reference to the response object (`getResponse()`/
  `setResponse()`), used by the introspection and hybrid-flow support above.

## (c) PHP8 compatibility shim - delete entirely

- **`OpenSSL.php`** - a patched copy of `Lcobucci\JWT\Signer\OpenSSL` (fixes a PHP8 `is_resource()`
  vs `is_bool()` check on OpenSSL key resources that lcobucci/jwt 3.4.x got wrong under PHP8).
  lcobucci/jwt 5.x (required by both league v9 and steverhoades v3) does not have this bug.
  **Delete this file**, its `require_once` in `Keys.php`, and the
  `error_reporting(E_ALL & ~E_DEPRECATED)` suppression in `endpoint.php` that was papering over the
  same generation of PHP8 deprecation noise.

## (d) New features with no upstream equivalent - keep, no upstream basis available

RFC7662 Introspection (`Introspector.php`, `IntrospectionValidators/*`,
`ResponseTypes/(Bearer)IntrospectionResponse.php`) - genuinely new, no upstream package implements
this even now (league issue #1473 still open). Client-specific token TTLs. `AdminCmds/Client.php`
(admin-cli client management). The token-management UI (`Ui.php`/`User.php`/`Token.php`/`Hooks.php`).
`groups`/`roles`/`email_aliases` claims/scopes. `well-known-configuration.php` (OpenID Discovery -
no upstream package implements this either).

## Known behavioral gap found while writing tests (not an "override", but worth fixing)

`Introspector::validateIntrospectionRequest()` only checks the HTTP method is `POST` - it never
actually verifies the requesting client's Basic-auth credentials against the token's `client_id`.
Any client (or no client at all) can introspect any token as long as they have the token string.
`openid/tests/IntrospectionTest.php` deliberately does NOT assert this is required (to avoid
encoding the gap as "correct" in the regression suite) - decide during the rewrite whether to add
proper client authentication to `/introspect`.
