<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: OpenID Discovery document contract test
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/OpenIDTestBase.php';

/**
 * GET /.well-known/openid-configuration (server root, see well-known-configuration.php)
 *
 * Contract under test: the OpenID Connect Discovery document (RFC/spec required + recommended
 * fields) is served with the right endpoint URLs, and honours conditional GETs via ETag. Pass
 * criteria: HTTP 200 with all required fields pointing at endpoint.php sub-paths, "openid" listed
 * in scopes_supported, and a repeated request with If-None-Match returns 304.
 */
class DiscoveryTest extends OpenIDTestBase
{
	protected static array $test_grants = ['client_credentials'];

	public function testRequiredFields() : void
	{
		$response = $this->httpClient()->get($this->discoveryUrl());
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);

		foreach(['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
			'response_types_supported', 'subject_types_supported',
			'id_token_signing_alg_values_supported'] as $required)
		{
			$this->assertArrayHasKey($required, $data, "Required field '$required' missing");
		}
		$this->assertStringEndsWith('/openid/endpoint.php/authorize', $data['authorization_endpoint']);
		$this->assertStringEndsWith('/openid/endpoint.php/access_token', $data['token_endpoint']);
		$this->assertStringEndsWith('/openid/endpoint.php/jwks', $data['jwks_uri']);
		$this->assertStringEndsWith('/openid/endpoint.php/userinfo', $data['userinfo_endpoint']);
		$this->assertContains('openid', $data['scopes_supported'] ?? []);
		$this->assertNotEmpty($data['end_session_endpoint'] ?? null);
	}

	public function testEtagConditionalGet() : void
	{
		$first = $this->httpClient()->get($this->discoveryUrl());
		$this->assertHttpStatus(200, $first);
		$etag = $first->getHeader('ETag')[0] ?? null;
		$this->assertNotEmpty($etag, 'ETag header missing');

		$second = $this->httpClient()->get($this->discoveryUrl(), [
			'headers' => ['If-None-Match' => $etag],
		]);
		$this->assertHttpStatus(304, $second, 'Matching If-None-Match must return 304');
	}
}
