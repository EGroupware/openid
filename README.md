# OpenID Connect and OAuth2 server for EGroupware

This is work in progress, do NOT install on a production server!

Open tasks:
- [ ] installation to automatic create public key pair and encryption key
- [ ] password grant: record and check failed login attempts like login page (see [user.authentication.failed](https://oauth2.thephpleague.com/authorization-server/events/))
- [ ] move to a single endpoint.php instead (implicit|auth_code|client_credentials|password).php
- [ ] limit clients to certain grant types and scopes (database schema supports that)
- [ ] UI to add clients as admin for all users or personal ones
- [ ] UI to view and revoke access- and refresh-tokes
- [ ] fix League OAuth2 server to support hybrid flow (currently it neither [splits response_type by space](https://github.com/thephpleague/oauth2-server/blob/master/src/Grant/ImplicitGrant.php#L109), nor does it send responses for more then one grant
- [ ] test with Rocket.Chat
- [ ] test with more clients

## Installation

0. Clone this repo into your EGroupware directory:
0. Run `composer install --prefer-source` in this directory to install dependencies
0. Create a private and public key pair in EGroupware's files directory

```
cd /path/to/egroupware/files
mkdir openid
openssl genrsa -out openid/private.key 2048
openssl rsa -in openid/private.key -pubout > openid/public.key
chgrp -R www-run openid
chmod -R o-rwx openid
```
## Testing available grants
A grant is a method of acquiring an access token. Deciding which grants to use depends on the type of client the end user will be using, and the experience you want for your users.

https://oauth2.thephpleague.com/authorization-server/which-grant/

All examples require to create a client first, eg. via the following SQL:
```
INSERT INTO `egw_openid_clients` (`client_name`, `client_identifier`, `client_secret`, `client_redirect_uri`, `client_created`) VALUES
('oidcdebugger.com', 'oidcdebugger.com', '$2y$10$n3ETBDdoXZDxcn9PUl2qyuKWjKxz.HW6o8ub8c/8FdYzdWL/qKjCu' /* "secret" */, 'https://oidcdebugger.com/debug', NOW());
```
The following test assume your EGroupware installation is reachable under http://example.com/egroupware/

## Testing the client credentials grant

Send the following cURL request:

```
curl -X "POST" "http://example.org/egroupware/openid/client_credentials.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=oidcdebugger.com" \
	--data-urlencode "client_secret=secret" \
	--data-urlencode "scope=openid email"
```

## Testing the password grant

Send the following cURL request (replacing <username>/<password> with one valid for your EGroupware!):

```
curl -X "POST" "http://example.org/egroupware/openid/password.php/access_token" \
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
Authorize URI: http://example.com/egroupware/openid/implicit.php/authorize
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
Authorize URI: http://example.com/egroupware/openid/auth_code.php/authorize
Redirect URI:  https://oidcdebugger.com/debug
Client ID:     oidcdebugger.com
Scope:         openid
Response Type: code
Response Mode: form_post
```
Hit [Send request] and you will be redirected to your EGroupware, have to log in, if you not already are, and authorize the request. After that you will be redirected back to the OpenID Connect debuger, which will show if it was successful and in that case and temporary auth-code which now needs to be exchanged in a 2. step into an access- and a refresh-token.
```
curl -X POST -i http://example.org/egroupware/openid/auth_code.php/access_token \
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
All 3 tokens and in case of the access-token also the scopes are now also in the egw_openid_(auth_codes|access_tokens|access_token_scopes|refres_tokens) tables.
