# OpenID Connect and OAuth2 server for EGroupware

## Supported endpoints and token issuer
* Authorization: https://example.org/egroupware/openid/endpoint.php/authorize
* Token: https://example.org/egroupware/openid/endpoint.php/access_token
* Token Introspection: https://example.org/egroupware/openid/endpoint.php/introspect
* User information: https://example.org/egroupware/openid/endpoint.php/userinfo
* Public key: https://example.org/egroupware/openid/endpoint.php/jwks
* Configuration: https://example.org/.well-known/openid-configuration
* Issuer: https://example.org
> Replace example.org with the full qualified domain-name your EGroupware server uses.

## Supported Grants:
* Authorization Code: user authorized access and get auth-code, server requests access-token via backchannel
* Refresh Token: token to refresh access-token after it's expired
* Client Credentials: server requests access-token without further authorization
* Implicit: user authorized access and get access-token and auth-code, server requests own access-token via backchannel
* Password Credential: other server checks username/password of EGroupware user (not recommended any more, as other server gets the password!)

## Client configuration in EGroupware
> Go to: Admin > Applications > OpenID / OAuth2 server > Clients

## More useful resources
* [Integration with various clients](https://github.com/EGroupware/egroupware/wiki/OpenID-Connect----OAuth2)
* [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)
* [The PHP League OAuth 2.0 Server](https://github.com/thephpleague/oauth2-server)
* [OpenID Connect Server plugin for The PHP League's OAuth2 Server](https://github.com/steverhoades/oauth2-openid-connect-server)
* [Diagrams of All The OpenID Connect Flows](https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660)
* [Identity, Claims, & Tokens – An OpenID Connect Primer](https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1) in 3 parts

## Open tasks:
- [ ] PHP 8.0 compatibility: temporary fix implemented using iii. until we're ready to update steverhoades/oauth2-openid-connect-server
  1. https://github.com/steverhoades/oauth2-openid-connect-server/pull/33 Support for lcobucci/jwt:4.0
  1. https://github.com/thephpleague/oauth2-server/pull/1146/files
  1. https://github.com/lcobucci/jwt/blob/4.0.x/composer.json#L20 lcobucci/jwt:4.0 support PHP 8 [PHP 8 for 3.4](https://github.com/lcobucci/jwt/pull/592/files)
- [ ] password grant: record and check failed login attempts like login page (see [user.authentication.failed](https://oauth2.thephpleague.com/authorization-server/events/))
- [ ] wrong password on login looses oath request in session and therefore fails after correct password was entered
- [ ] test with more clients, e.g. [Dovecot](https://wiki2.dovecot.org/PasswordDatabase/oauth2)
- [ ] token endpoint must support response_type=code+id_token
- [ ] allow users to create personal clients
- [ ] implement full [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [x] /.well-known/openid-configuration is supported now
- [x] token endpoint must return nonce of authorization request as claim in id_token
- [x] fix League OAuth2 server to support multiple response_type(s), currently it neither [splits response_type by space](https://github.com/thephpleague/oauth2-server/blob/master/src/Grant/ImplicitGrant.php#L109), nor does it send responses for more then one grant, [see response in this ticket](https://github.com/thephpleague/oauth2-server/issues/903#issuecomment-423891504)
- [x] support response_type "id_token" or "token id_token" containing just an id_token (JWT) or additional to access_token an id_token
- [x] support hyprid flow / response_type contains additional "code" to also return an auth_code
- [x] allow to create clients, which behave like an EGroupware App:
    * added to egw_applications
    * authentication for them works only if user has run-rights for that application
    * an extra defined index-url get's opened as iframe inside EGroupware framework
- [x] UI to view and revoke access- and refresh-tokens
- [x] UI to add clients as admin for all users
- [x] move to a single endpoint.php instead (implicit|auth_code|client_credentials|password).php
- [x] add additional [OpenID Connect standard scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims): profile, address, phone
- [x] implement [OpenID Connect /userinfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
- [x] test with Rocket.Chat, see below for Rocket.Chat custom OAuth configuration
- [x] add [oauth2-server pull request #925](https://github.com/thephpleague/oauth2-server/pull/925) to implement [RFC7662 OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662) to allow clients to validate tokens
- [x] automatic generation of public key pair and encryption key on first use
- [x] limit clients to certain grant types and scopes (database schema supports that)

## Installation

1. EGroupware master and 19.1 install this app by default: composer install or install-cli.php
2. Install openid app via EGroupware setup

## Testing available grants
A grant is a method of acquiring an access token. Deciding which grants to use depends on the type of client the end user will be using, and the experience you want for your users.

https://oauth2.thephpleague.com/authorization-server/which-grant/

All examples require to create a client under Admin >> OpenID / OAuth2 server >> Clients with ALL grants first:
```
Name:           oidcdebugger.com
Identifier:     oidcdebugger.com
Secret:         secret
Redirect URI:   https://oidcdebugger.com/debug
Allowed Grants: select all available ones
Limit Scopes:   don't select one
Status:         Active
```
The following test assume your EGroupware installation is reachable under http://example.com/egroupware/

## Testing the client credentials grant

Send the following cURL request:

```
curl -X "POST" "http://example.org/egroupware/openid/endpoint.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=oidcdebugger.com" \
	--data-urlencode "client_secret=secret" \
	--data-urlencode "scope=openid email"
```

## Testing the password grant

Send the following cURL request (replacing &lt;username>/&lt;password> with one valid for your EGroupware!):

```
curl -X "POST" "http://example.org/egroupware/openid/endpoint.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=password" \
	--data-urlencode "client_id=oidcdebugger.com" \
	--data-urlencode "client_secret=secret" \
	--data-urlencode "username=<username>" \
	--data-urlencode "password=<password>" \
	--data-urlencode "scope=openid email"
```

## Testing the implicit grant

Here we use the OpenID Connect Debugger site, so head to https://oidcdebugger.com and add the following data:
```
Authorize URI: http://example.com/egroupware/openid/endpoint.php/authorize
Redirect URI:  https://oidcdebugger.com/debug
Client ID:     oidcdebugger.com
Scope:         openid
Response Type: token
Response Mode: form_post
```
Hit [Send request] and you will be redirected to your EGroupware, have to log in, if you not already are, and authorize the request. After that you will be redirected back to the OpenID Connect debuger, which will show if it was successful and in that case the access-token. It should also generate a row in egw_openid_access_token and egw_open_id_access_token_scopes table.

## Testing the authorization code grant

Here we use again the OpenID Connect Debugger site for the first step, so head to https://oidcdebugger.com and change the URI and Response code as below:
```
Authorize URI: http://example.com/egroupware/openid/endpoint.php/authorize
Redirect URI:  https://oidcdebugger.com/debug
Client ID:     oidcdebugger.com
Scope:         openid
Response Type: code
Response Mode: form_post
```
Hit [Send request] and you will be redirected to your EGroupware, have to log in, if you not already are, and authorize the request. After that you will be redirected back to the OpenID Connect debuger, which will show if it was successful and in that case and temporary auth-code which now needs to be exchanged in a 2. step into an access- and a refresh-token.
```
curl -X POST -i http://example.org/egroupware/openid/endpoint.php/access_token \
	-H "Content-Type: application/x-www-form-urlencoded" \
	--data-urlencode "grant_type=authorization_code" \
	--data-urlencode "code=<auth-code-displayed-by-debugger>" \
	--data-urlencode "client_id=oidcdebugger.com" \
	--data-urlencode "client_secret=secret" \
	--data-urlencode "redirect_uri=https://oidcdebugger.com/debug"

HTTP/1.1 200 OK
Date: Fri, 05 Apr 2019 06:42:29 GMT
Server: Apache/2.4.38 (Unix) OpenSSL/1.0.2r PHP/7.3.3
X-Powered-By: PHP/7.3.3
pragma: no-cache
cache-control: no-store
Content-Length: 2132
Content-Type: application/json; charset=UTF-8

{"id_token":"<token-id>","token_type":"Bearer","expires_in":3600,"access_token":"<access-token>","refresh_token":"<refresh-token"}
```
All 3 tokens and in case of the access-token also the scopes are now also in the egw_openid_(auth_codes|access_tokens|access_token_scopes|refresh_tokens) tables.

## Testing /userinfo endpoint

You need a valid access_token, which you can get eg. with an implicit grant (see above), using scopes: openid profile email phone address
```
curl -i "http://example.org/egroupware/openid/endpoint.php/userinfo" \
	-H 'Accept: application/json' \
	-H "Authorization: Bearer <access-token>"
HTTP/1.1 200 OK
Date: Sat, 06 Apr 2019 18:16:38 GMT
Server: Apache/2.4.38 (Unix) OpenSSL/1.0.2r PHP/7.3.3
X-Powered-By: PHP/7.3.3
pragma: no-cache
cache-control: no-store
Content-Length: 381
Content-Type: application/json; charset=UTF-8

{"sub":"5","name":"Ralf Becker","family_name":"Becker","given_name":"Ralf","middle_name":null,"nickname":"","preferred_username":"ralf","profile":"","picture":"https:\/\/www.gravatar.com\/avatar\/b7d0e97f58c03dd3fed9753fa25293dc","website":"http:\/\/www.egroupware.org\/","gender":"n\/a","birthdate":"1970-01-01","zoneinfo":"Europe\/Berlin","locale":"DE","updated_at":"2018-12-07"}```
```
## Testing /introspect endpoint with a client-id and -secret

You need an access_token to test, which you can get eg. with an implicit grant (see above).

The basic authorization header below uses: base64_encode("&lt;client-id>:&lt;client-secret>").
```
curl -i "http://example.org/egroupware/openid/endpoint.php/introspect" \
	-H "Accept: application/json" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Authorization: Basic b2lkY2RlYnVnZ2VyLmNvbTpzZWNyZXQ=" \
	--data-urlencode "token=<access-token>"
	--data-urlencode "token_type_hint=access_token"
HTTP/1.1 200 OK
Date: Sun, 07 Apr 2019 09:17:44 GMT
Server: Apache/2.4.38 (Unix) OpenSSL/1.0.2r PHP/7.3.3
X-Powered-By: PHP/7.3.3
pragma: no-cache
cache-control: no-store
Content-Length: 236
Content-Type: application/json; charset=UTF-8

{"active":true,"token_type":"access_token","scope":["openid","profile"],"client_id":"oidcdebugger.com","exp":1554629779,"iat":1554626179,"sub":"2","jti":"2ab5f9fe5f4cfe0eeb49491e4cc9a313b2fb11f74969d52b8bd60ba8ec9894ae7f1c9eee697e74f2"}
```
