<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: client_credentials grant contract test
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/OpenIDTestBase.php';

use GuzzleHttp\RequestOptions;

/**
 * POST /access_token grant_type=client_credentials
 *
 * Contract under test: a confidential client can authenticate with its client_id/secret alone
 * (no user involved) and receive a bearer access_token; no refresh_token is issued for this grant
 * (there's no user to re-authorize). Pass criteria: HTTP 200, JSON body with token_type=Bearer,
 * a non-empty access_token and expires_in, and NO refresh_token key.
 */
class ClientCredentialsGrantTest extends OpenIDTestBase
{
	protected static array $test_grants = ['client_credentials'];

	public function testIssuesAccessToken() : void
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'client_credentials',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(200, $response);

		$data = $this->jsonDecode($response);
		$this->assertSame('Bearer', $data['token_type'] ?? null, 'token_type must be Bearer');
		$this->assertNotEmpty($data['access_token'] ?? null, 'access_token missing');
		$this->assertGreaterThan(0, $data['expires_in'] ?? 0, 'expires_in missing/invalid');
		$this->assertArrayNotHasKey('refresh_token', $data,
			'client_credentials grant must not issue a refresh_token (no user to re-authorize)');
	}

	public function testWrongSecretRejected() : void
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'client_credentials',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => 'wrong-secret',
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(401, $response, 'Wrong client_secret must be rejected');
		$data = $this->jsonDecode($response);
		$this->assertSame('invalid_client', $data['error'] ?? null);
	}

	public function testGrantNotAllowedForClientRejected() : void
	{
		// this test's client only has client_credentials enabled (self::$test_grants above)
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'password',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'username' => $this->testAccountLid(),
				'password' => $GLOBALS['EGW_PASSWORD'],
				'scope' => 'openid',
			],
		]);
		// rejected as unauthorized_client (400): ClientEntity::supportsGrantType() returns false
		// since this client has no 'password' row in egw_openid_client_grants.
		$this->assertHttpStatus(400, $response, 'Grant not enabled for client must be rejected');
		$data = $this->jsonDecode($response);
		$this->assertSame('unauthorized_client', $data['error'] ?? null);
	}
}
