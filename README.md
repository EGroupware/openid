# OpenID Connect and OAuth2 server for EGroupware

This is work in progress, do NOT install on a production server!

## Installation

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
A grant is a method of acquiring an access token. Deciding which grants to implement depends on the type of client the end user will be using, and the experience you want for your users.
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
curl -i --data "grant_type=authorization_code" \
	--data "code=<auth-code-displayed-by-debugger>" \
	--data "client_id=oidcdebugger.com" \
	--data "client_secret=secret" \
	--data "redirect_uri=https://oidcdebugger.com/debug" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	http://example.org/egroupware/openid/auth_code.php/access_token

HTTP/1.1 200 OK
Date: Fri, 05 Apr 2019 06:42:29 GMT
Server: Apache/2.4.38 (Unix) OpenSSL/1.0.2r PHP/7.3.3
X-Powered-By: PHP/7.3.3
pragma: no-cache
cache-control: no-store
Content-Length: 2132
Content-Type: application/json; charset=UTF-8

{"id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJvaWRjZGVidWdnZXIuY29tIiwiaXNzIjoiaHR0cDpcL1wvYm91bGRlci5lZ3JvdXB3YXJlLm9yZyIsImlhdCI6MTU1NDQ0NjU1NSwiZXhwIjoxNTU0NDUwMTU1LCJzdWIiOiI1In0.HSFZrgqnO7fpCDToVUfB0TbucdBxOMms9a8ZKGnIDUou-7shcJHp2XqD9bQ27v1oYS90SughVPDvh351-gj5amhq-XB7RrCr_m3PqHLvETalIjpf5iYrHjfX9T84ttJTlcPAVT5hJz16BT7NLTY92WgQDBrjmZpIP6iQSamQqyui63yP-YcKbxVSfgWCmlrVW0Q6dxL8EpZRHO314T23czT4jzd6tSEleyQxlglTgpxYFJ1-e_I9mjxIBZLLcFx50aQ8j0fomu6IMeJkIYdms9mSFSotCHEfr-l0KBUw2xiQ1vukm1gtbFA6VOV8hRFjxkqgBMliqtyb2L-rQSiX9A","token_type":"Bearer","expires_in":3600,"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjcyZWE5MGI5YzFmNzgxMDFkYjNkNjM2Yjg2ZmFiZjMxN2U0ZmVlMmE3OTVjMzQ4NzkzZTgyMmM0MjlmN2FhYTQwYTY0MDg4NjgwYzk3OTI3In0.eyJhdWQiOiJvaWRjZGVidWdnZXIuY29tIiwianRpIjoiNzJlYTkwYjljMWY3ODEwMWRiM2Q2MzZiODZmYWJmMzE3ZTRmZWUyYTc5NWMzNDg3OTNlODIyYzQyOWY3YWFhNDBhNjQwODg2ODBjOTc5MjciLCJpYXQiOjE1NTQ0NDY1NTUsIm5iZiI6MTU1NDQ0NjU1NSwiZXhwIjoxNTU0NDUwMTU1LCJzdWIiOiI1Iiwic2NvcGVzIjpbIm9wZW5pZCJdfQ.kv64nXkTJvKfNyVqx-HWV1P1J4je8IrpUrXmOpDk89Kulci76ogHAshGr6wpl2YAie5egxnBRBFpQJM5obxIBkhbTRPAPqJETK7_gP-SXEWyBMdFAZYYY2Eli02z7ob7HX8pxmRx5U1svtf0XnVVaee-ukl5CQhvBF8XbS8tvkpsY6gSMp8fbFWEqaezssEZ43TkEluFT5RevJz8pbZkddMJW5CkD1BC9jO-1K-lFKNXpW83qQd1QjNBysbllaDhHcbUIN6fqQar1ENohDnbhaPHivhK1fka7gBhVWM2JmWaLoswY1lTrvYBQ6hjEj1T81dUDTUa-cpWfNh7_6ZykQ","refresh_token":"def50200d377a7b4d4a7349f6c54663bab53b529f04fa255f6427b7ad18703e48a8619f1b867174853eb38879e1ec27cb425d81d85f52116fcd74da364513731f04328f89e34054e34a5f2f3ca8d8da40b53076b8dc7faea26761abd14771e9c0f65e51e5e281c7882859d1d5b418e4ee0ee91d6bf797540c95967f52fd225164a2ae1b52a83e2f54d4abc6c70bde25a29fa8aa288e3436e5164688fe47fe4e0e8ee4fc1b3c75e9f131b26c971fa023badf00ff89296fa88393d01b1cb88b97fbbf14a45295a2d697ed5f049ba7be6ec40a7bd765cb62fa372d99a6514378b446328d073cd4a9a6af9ac9a6addfbb4998854ea973853ca1b36edd3f78e388ab9c74277f13f5e380a0c22644e5aeb26acbf4a01744e8250b2dffe49d1ab003a7ff25fcc5e8993ce7a027b6f9a368c47f8ee8c797043044123407014a634918401482049685b685177867605cbfc0ea152bdad643878f4ff45ac888dae64af61fd2e47ed3c46a45907e6116ce4f411f7d15a9c0b1408a0a1d6"}
```
Alle 3 tokens and in case of the access-token also the scopes are now also in the egw_openid_(auth_codes|access_tokens|access_token_scopes|refres_tokens) tables.
