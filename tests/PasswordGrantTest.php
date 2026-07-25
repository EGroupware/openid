<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: password grant contract test
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
 * POST /access_token grant_type=password
 *
 * Contract under test: a client can exchange an EGroupware username/password directly for an
 * access_token + refresh_token bound to that user (used eg. by Dovecot). Pass criteria: HTTP 200,
 * access_token + refresh_token present; wrong password rejected with HTTP 401 invalid_credentials
 * and does NOT reveal whether the account itself exists.
 */
class PasswordGrantTest extends OpenIDTestBase
{
	protected static array $test_grants = ['password'];

	public function testIssuesAccessAndRefreshToken() : void
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'password',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'username' => $this->testAccountLid(),
				'password' => $GLOBALS['EGW_PASSWORD'],
				'scope' => 'openid profile',
			],
		]);
		$this->assertHttpStatus(200, $response);

		$data = $this->jsonDecode($response);
		$this->assertSame('Bearer', $data['token_type'] ?? null);
		$this->assertNotEmpty($data['access_token'] ?? null, 'access_token missing');
		$this->assertNotEmpty($data['refresh_token'] ?? null, 'refresh_token missing');
	}

	public function testWrongPasswordRejected() : void
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'password',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'username' => $this->testAccountLid(),
				'password' => 'definitely-wrong-password',
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(401, $response);
		$data = $this->jsonDecode($response);
		$this->assertSame('invalid_credentials', $data['error'] ?? null,
			'Wrong credentials must map to invalid_credentials, not leak account existence');
	}
}
