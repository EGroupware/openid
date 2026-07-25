<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: refresh_token grant contract test
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
 * POST /access_token grant_type=refresh_token
 *
 * Contract under test: a refresh_token obtained from the password grant can be exchanged for a
 * new access_token (+ a new refresh_token, rotation), and the OLD refresh_token is revoked
 * (single use). Pass criteria: first exchange returns HTTP 200 with a new access_token/
 * refresh_token pair different from the original; reusing the original refresh_token afterwards
 * is rejected with HTTP 400.
 */
class RefreshTokenGrantTest extends OpenIDTestBase
{
	protected static array $test_grants = ['password', 'refresh_token'];

	protected function getRefreshToken() : string
	{
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
		$this->assertHttpStatus(200, $response, 'fixture password-grant token request failed');
		$data = $this->jsonDecode($response);
		$this->assertNotEmpty($data['refresh_token'] ?? null);
		return $data['refresh_token'];
	}

	public function testRefreshRotatesToken() : void
	{
		$refresh_token = $this->getRefreshToken();

		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'refresh_token',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'refresh_token' => $refresh_token,
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);
		$this->assertNotEmpty($data['access_token'] ?? null, 'access_token missing');
		$this->assertNotEmpty($data['refresh_token'] ?? null, 'refresh_token missing');
		$this->assertNotSame($refresh_token, $data['refresh_token'], 'refresh_token must rotate');

		// old refresh_token must now be revoked (single use)
		$reuse = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'refresh_token',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'refresh_token' => $refresh_token,
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(401, $reuse, 'reusing a rotated-out refresh_token must be rejected');
	}

	public function testInvalidRefreshTokenRejected() : void
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'refresh_token',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'refresh_token' => 'not-a-real-token',
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(401, $response);
	}
}
