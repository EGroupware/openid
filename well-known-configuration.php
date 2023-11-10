<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @link https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
 */

use EGroupware\Api;
use EGroupware\OpenID;

$GLOBALS['egw_info'] = array(
	'flags' => array(
		// only /authorize needs a session, /access_token does not
		'currentapp'	=> 'login',
		'nonavbar'		=> True,
		'noheader'      => True,
		'autocreate_session_callback' => Authorize::class.'::anon_session',
	));
include('../header.inc.php');

$endpoint = Api\Framework::getUrl(Api\Framework::link('/openid/endpoint.php'));
$issuer = preg_replace('#^(https?://[^/]+)/.*$#', '$1', $endpoint);
$scope_repo = new OpenID\Repositories\ScopeRepository();

$content = json_encode([
	// required
	"issuer" => $issuer,
	"authorization_endpoint" => "$endpoint/authorize",
	"token_endpoint" => "$endpoint/access_token",
	"jwks_uri" => "$endpoint/jwks",
	"response_types_supported" => ["code", "code id_token", "id_token", "token id_token"],
	"subject_types_supported" => ["public", "pairwise"],    // check?
	"id_token_signing_alg_values_supported" => ["RS256", "ES256", "HS256"], // check?
	// recommended
	"userinfo_endpoint" => "$endpoint/userinfo",
	"claims_supported" => [
		"sub", "iss", //"auth_time", "acr",
		"name", "given_name", "family_name", "nickname",
		"profile", "picture", "website",
		"email", "email_verified", "locale", "zoneinfo",
		"roles" /* "user", "admin" */, "groups",
	],
	// "registration_endpoint" => "https://server.example.com/connect/register",
	"scopes_supported" => array_keys($scope_repo->getScopes()),
	// optional
	"response_modes_supported" => ["query", /* "fragment" check? */],
	"grant_types_supported" => [
		/* required */ "authorization_code", "implicit",
		/* optional */ "refresh_token", "client_credentials", "password_credentials"
	],
	//"acr_values_supported" => ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
	//"id_token_encryption_alg_values_supported" => ["RSA1_5", "A128KW"],
	//"id_token_encryption_enc_values_supported" => ["A128CBC-HS256", "A128GCM"],
	//"userinfo_signing_alg_values_supported" => ["RS256", "ES256", "HS256"],
	//"userinfo_encryption_alg_values_supported" => ["RSA1_5", "A128KW"],
	//"userinfo_encryption_enc_values_supported" => ["A128CBC-HS256", "A128GCM"],
	//"request_object_signing_alg_values_supported" => ["none", "RS256", "ES256"],
	//"request_object_encryption_alg_values_supported =>
	//"request_object_encryption_enc_values_supported" =>
	"token_endpoint_auth_methods_supported" => ["client_secret_basic", /* check: "client_secret_post", "client_secret_jwt", "private_key_jwt"*/],
	//"token_endpoint_auth_signing_alg_values_supported" => ["RS256", "ES256"],
	"display_values_supported" => ["page", "popup", /*"touch", "wap" */],
	"claim_types_supported" => ["normal", /* "distributed" */],
	"service_documentation" => "https://github.com/EGroupware/openid",
	//"claims_locales_supported" =>
	//"ui_locales_supported" => ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
	//"claims_parameter_supported" => true,
	//"request_parameter_supported" => true,
	"request_uri_parameter_supported" => true,  // default
	"require_request_uri_registration" => true, // default
	//"op_policy_uri" =>
	//"op_tos_uri" =>
	// https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata
	//"check_session_iframe" => "https://server.example.com/connect/check_session",
	"end_session_endpoint" => Api\Framework::getUrl(Api\Framework::link('/logout.php')),
], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
$etag = '"'.md5($content).'"';

// headers to allow caching, egw_framework specifies etag on url to force reload, even with Expires header
Api\Session::cache_control(864000);	// cache for 10 days
Header('Content-Type: application/json');
Header('ETag: '.$etag);

// if servers send a If-None-Match header, response with 304 Not Modified, if etag matches
if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && $_SERVER['HTTP_IF_NONE_MATCH'] === $etag)
{
	header("HTTP/1.1 304 Not Modified");
	exit;
}

Header('Content-Length: '.bytes($content));
echo $content;