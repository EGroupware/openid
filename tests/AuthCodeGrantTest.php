<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: authorization_code grant contract test
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
 * GET /authorize response_type=code, then POST /access_token grant_type=authorization_code
 *
 * The consent screen itself (Api\Etemplate popup) is a UI concern outside this HTTP contract, so
 * these tests seed a pre-existing refresh-token (see OpenIDTestBase::seedRefreshToken()), which
 * makes Authorize::requireApproval() skip the interactive dialog exactly like it would for a
 * client the user already approved before - the same code path a returning user takes.
 *
 * Contract under test: a logged-in user hitting /authorize gets redirected (302) with an auth
 * "code" (+ echoed "state"); exchanging that code at /access_token yields access_token,
 * refresh_token and an id_token whose "nonce" claim matches what was sent to /authorize (required
 * by the OpenID Connect spec, fixed for Moodle's auth_oidc plugin - see
 * openid/doc/UPSTREAM-OVERRIDES.md).
 */
class AuthCodeGrantTest extends OpenIDTestBase
{
	// refresh_token must also be enabled: league/oauth2-server 9 only issues a refresh_token if
	// the client's grants include 'refresh_token' (AbstractGrant::issueRefreshToken() checks
	// ClientEntity::supportsGrantType('refresh_token'))
	protected static array $test_grants = ['authorization_code', 'refresh_token'];

	protected function decodeJwtPayload(string $jwt) : array
	{
		$parts = explode('.', $jwt);
		$this->assertCount(3, $parts, 'not a JWT');
		return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true) ?: [];
	}

	public function testFullFlowWithNonce() : void
	{
		$this->seedRefreshToken(['openid']);

		$client = $this->httpLogin();
		if ($client === null)
		{
			$this->markTestSkipped('Could not establish an HTTP-authenticated session for '.
				$this->testAccountLid().' (see httpLogin(); eg. account may be expired in this environment)');
		}

		$state = bin2hex(random_bytes(8));
		$nonce = bin2hex(random_bytes(8));
		$authorize = $client->get($this->endpointUrl('/authorize'), [
			RequestOptions::ALLOW_REDIRECTS => false,
			RequestOptions::QUERY => [
				'response_type' => 'code',
				'client_id' => $this->clientIdentifier(),
				'redirect_uri' => self::REDIRECT_URI,
				'scope' => 'openid',
				'state' => $state,
				'nonce' => $nonce,
			],
		]);
		$this->assertHttpStatus([302, 303], $authorize,
			'Expected a redirect back to redirect_uri with an auth code (consent bypassed via seeded refresh-token)');
		$location = $authorize->getHeader('Location')[0] ?? '';
		$this->assertStringStartsWith(self::REDIRECT_URI, $location, 'Redirect must go to the registered redirect_uri');
		parse_str((string)parse_url($location, PHP_URL_QUERY), $params);
		$this->assertNotEmpty($params['code'] ?? null, 'auth code missing from redirect');
		$this->assertSame($state, $params['state'] ?? null, 'state must be echoed back unchanged');

		$token_response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'authorization_code',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'redirect_uri' => self::REDIRECT_URI,
				'code' => $params['code'],
			],
		]);
		$this->assertHttpStatus(200, $token_response);
		$data = $this->jsonDecode($token_response);
		$this->assertNotEmpty($data['access_token'] ?? null, 'access_token missing');
		$this->assertNotEmpty($data['refresh_token'] ?? null, 'refresh_token missing');
		$this->assertNotEmpty($data['id_token'] ?? null, 'id_token missing (OpenID Connect requires it for scope=openid)');

		$id_token_claims = $this->decodeJwtPayload($data['id_token']);
		$this->assertSame($nonce, $id_token_claims['nonce'] ?? null,
			'id_token must carry the nonce sent in the original /authorize request');
	}

	public function testAuthCodeIsSingleUse() : void
	{
		$this->seedRefreshToken(['openid']);
		$client = $this->httpLogin();
		if ($client === null)
		{
			$this->markTestSkipped('Could not establish an HTTP-authenticated session for '.$this->testAccountLid());
		}

		$authorize = $client->get($this->endpointUrl('/authorize'), [
			RequestOptions::ALLOW_REDIRECTS => false,
			RequestOptions::QUERY => [
				'response_type' => 'code',
				'client_id' => $this->clientIdentifier(),
				'redirect_uri' => self::REDIRECT_URI,
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus([302, 303], $authorize);
		parse_str((string)parse_url($authorize->getHeader('Location')[0] ?? '', PHP_URL_QUERY), $params);
		$this->assertNotEmpty($params['code'] ?? null);

		$exchange_once = fn() => $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'authorization_code',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'redirect_uri' => self::REDIRECT_URI,
				'code' => $params['code'],
			],
		]);
		$this->assertHttpStatus(200, $exchange_once(), 'first exchange of a fresh auth code must succeed');
		$this->assertHttpStatus(400, $exchange_once(), 'reusing an already-exchanged auth code must be rejected');
	}
}
