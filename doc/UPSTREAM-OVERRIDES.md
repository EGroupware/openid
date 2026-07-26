# Upstream overrides audit

Catalog of every `src/` class that forks, patches or extends upstream code (as opposed to
EGroupware-specific storage/UI integration), why it exists, and what should happen to it once
the app is rebased on current upstream releases (see the feature-branch rewrite plan). Vendored
versions when this catalog was first written (on `master`): `league/oauth2-server` 7.4.0,
`steverhoades/oauth2-openid-connect-server` 1.3.0, `lcobucci/jwt` 3.4.6, `slim/slim` 3.13.0. The
"Rewrite status" section below records what changed on the `upstream-rebase-2026` branch.

## (a) EGroupware integration code (not an override - keep as-is)

The storage layer: `Repositories/{Client,AccessToken,AuthCode,RefreshToken,Scope,User,Identity,Grant,Base}.php`,
`Entities/{Client,AccessToken,AuthCode,RefreshToken,Scope,User}Entity.php` (+ `Entities/Traits/*`).
Plus `Keys.php`, `Authorize.php`, `Hooks.php`, `Log/*`, `Ui.php`, `User.php`, `AdminCmds/Client.php`.
These implement upstream *interfaces* (see table below) but contain no copied upstream logic - they
are pure EGroupware integration and were reused as-is, only adapting to interface signature changes
forced by the new league/oauth2-server version (see "API migration notes" below). `Token.php` is
the one exception in this group - see "Not yet resolved" further down.

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

## Rewrite status (`upstream-rebase-2026` branch)

Done: `endpoint.php` bootstrap rewritten for Slim 4; `AuthorizationServer.php` now *extends*
`League\OAuth2\Server\AuthorizationServer` (was a full copy) with only `respondToAccessTokenRequest()`
(client TTL) and `completeAuthorizationRequest()` (carries response type for id_token) overridden,
plus the introspection methods; `Grant/ImplicitGrant.php` still has to extend
`AbstractAuthorizeGrant` directly (league v9's own `ImplicitGrant` dropped hybrid-flow/multi
response_type support entirely - only handles plain `response_type=token` now); all
Repositories/Entities updated for v9's typed, split interfaces (see "API migration notes" below);
`ClientEntity` gained `isConfidential()`/`supportsGrantType()` (from `ClientTrait`, was previously
enforced via a SQL join in `ClientRepository::getClientEntity()`); `IdTokenResponse.php`,
`BearerTokenValidator.php`, `BearerTokenIntrospectionResponse.php` and `AccessTokenEntity.php`
rewritten for lcobucci/jwt 5.x's immutable `Token\Builder`/`Validator`/`Constraint\*` API (was
lcobucci/jwt 3.x's `Builder`/`Parser`/`->sign()->getToken()`). All 31 `openid/tests/*` pass against
the new stack (`league/oauth2-server` 9.4, `steverhoades` v3.0.1, `slim/slim` 4.15, `lcobucci/jwt`
5.6, `lcobucci/clock` 3.6).

**Not yet resolved: `Token.php` (used by the `rocketchat` app's SSO integration, called from a hook
that runs on every EGroupware page).** `EGroupware\OpenID\Token` generates JWTs using our upgraded
lcobucci/jwt 5.x, but by the time it runs (mid-request, from inside an already-running EGroupware
page), `header.inc.php` has already loaded EGroupware's *main* `vendor/autoload.php`, which for
`lcobucci/jwt` 3.4.6 (pulled in by the `egroupware/status` app) unconditionally runs
`compat/class-aliases.php`:
```php
class_exists(Token\Plain::class, false) || class_alias(Token::class, Token\Plain::class);
```
Since our namespaced `Token\Plain` hasn't been touched yet at that point, this permanently
aliases it to the *old*, incompatible `Lcobucci\JWT\Token` class for the rest of that PHP
process - `class_alias()` cannot be undone. `endpoint.php` avoids this entirely because it's its
own request from the very start (our vendor loads before `header.inc.php` ever gets a chance to
run this shim) - `Token.php`, invoked mid-request from a hook, has no such luck; no autoload
ordering trick can fix it. `Token::accessToken()` currently catches the resulting `TypeError` and
returns `null` (logged via `_egw_log_exception`) so this degrades to "SSO token unavailable"
instead of a fatal 500 on every single EGroupware page - but the underlying capability doesn't
work. Real fixes (needs a decision, not yet made): get `egroupware/status` off lcobucci/jwt 3.x, or
have `rocketchat`'s SSO call the HTTP `/access_token` endpoint instead of instantiating
`EGroupware\OpenID\Token` in-process.

The same class-identity problem also hit `Lcobucci\Clock\Clock`/`SystemClock`/`FrozenClock` (same
compat shim, `interface_exists()`-gated instead of `class_alias()`-gated) - added `lcobucci/clock`
as an explicit dependency and preloaded it the same way, since `endpoint.php` DOES control its own
load order. See the `class_exists(...)` preload block at the top of `endpoint.php` before
`header.inc.php` is included, and the `$openid_loader->unregister(); $openid_loader->register(true);`
re-prepend right after it - both are required for `endpoint.php` to keep working and are not
optional cleanup.

## API migration notes (league/oauth2-server 7 -> 9, steverhoades 1 -> 3, lcobucci/jwt 3 -> 5)

For whoever picks this up next / reviews the diff:

- `ClientRepositoryInterface::getClientEntity()` lost its `$grantType`/`$clientSecret`/
  `$mustValidateSecret` params (now just `getClientEntity(string $clientIdentifier): ?ClientEntityInterface`).
  Secret validation moved to a new `validateClient(string $id, ?string $secret, ?string $grantType): bool`
  method; per-client grant restriction moved to `ClientEntityInterface::supportsGrantType()`
  (duck-typed via `method_exists()` in `AbstractGrant::getClientEntityOrFail()`, not part of the
  formal interface yet).
- Rejecting a grant a client isn't allowed to use now throws `unauthorizedClient()` (400
  `unauthorized_client`), not `invalidClient()` (401 `invalid_client`) as before.
- `OAuthServerException::invalidCredentials()` (wrong password) and `invalidRefreshToken()` both
  now map to 400 `invalid_grant` (previously 401 `invalid_credentials`/`invalid_request`
  respectively) - RFC6749-compliance fix on league's side.
- **New in v9: `AbstractGrant::issueRefreshToken()` only issues a refresh_token if
  `$client->supportsGrantType('refresh_token')` is true.** A client must have the `refresh_token`
  grant explicitly enabled (not just `password`/`authorization_code`) to receive one - this is a
  behavior change from v7, not a bug; test fixtures were updated accordingly.
- `TokenInterface::setExpiryDateTime()` / claim getters take/return `DateTimeImmutable`, not
  `DateTime`. `TokenEntityTrait::setUserIdentifier()` takes non-nullable `string` (client_credentials
  grants must simply not call it, rather than passing null).
- `ResponseTypeInterface::generateHttpResponse()` and `AuthorizationRequestInterface`'s setters
  (`setState()`, `setCodeChallenge()`, `setCodeChallengeMethod()`) are now non-nullable/typed;
  our `AuthorizationRequest::extend()` has to guard the optional ones (state/PKCE) before calling.
- lcobucci/jwt: `Builder`/`Parser` moved to `Token\Builder`/`Token\Parser`, immutable
  (`->withClaim()` returns a new instance, not `->set()`), signing is
  `$builder->getToken($signer, $key)` not `->sign($signer, $key)->getToken()`. Verification moved
  from `$token->verify()`/`$token->validate()` to `Configuration::validator()->validate($token,
  ...Constraint\*)`. Keys are `Signer\Key\InMemory::plainText()/file()`, not `Signer\Key`
  (now an interface). `permittedFor()` (aud) always stores an array even for a single audience.
