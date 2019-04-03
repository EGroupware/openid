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

## Testing the client credentials grant example

Send the following cURL request:

```
curl -X "POST" "http://example.org/egroupware/openid/client_credentials.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "scope=openid email"
```

## Testing the password grant example

Send the following cURL request:

```
curl -X "POST" "hhttp://example.org/egroupware/openid/password.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=password" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "username=<username>" \
	--data-urlencode "password=<password>" \
	--data-urlencode "scope=openid email"
```
