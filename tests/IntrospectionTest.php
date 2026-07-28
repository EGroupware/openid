<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: RFC7662 /introspect contract test
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/OpenIDTestBase.php';

use GuzzleHttp\RequestOptions;
use EGroupware\OpenID\Repositories\AccessTokenRepository;
use EGroupware\OpenID\Repositories\ClientRepository;
use EGroupware\OpenID\Entities\ClientEntity;

/**
 * POST /introspect (RFC7662 OAuth 2.0 Token Introspection)
 *
 * This is a genuinely new feature (no upstream league/oauth2-server support even as of v9, see
 * openid/doc/UPSTREAM-OVERRIDES.md) that MUST be preserved unchanged by the planned rewrite.
 *
 * Contract under test: a client authenticated with Basic auth can introspect a token it holds
 * and get back active/scope/client_id/exp/iat/sub/jti for a live token, and "active":false
 * (still HTTP 200, per RFC7662) for a revoked or malformed token, or one introspected without
 * valid client credentials, with wrong credentials, or by a client other than the one the
 * token was issued to.
 */
class IntrospectionTest extends OpenIDTestBase
{
	protected static array $test_grants = ['client_credentials'];

	protected function decodeJwtPayload(string $jwt) : array
	{
		$parts = explode('.', $jwt);
		$this->assertCount(3, $parts, 'access_token is not a JWT');
		return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true) ?: [];
	}

	/**
	 * @param string      $token
	 * @param string|false $authHeader Authorization header value; defaults to the test client's
	 *  own Basic auth; pass false to send no Authorization header at all
	 */
	protected function introspect(string $token, $authHeader=null) : \Psr\Http\Message\ResponseInterface
	{
		$headers = [];
		if ($authHeader !== false)
		{
			$headers['Authorization'] = $authHeader ?? $this->clientBasicAuthHeader();
		}
		return $this->httpClient()->post($this->endpointUrl('/introspect'), [
			'headers' => $headers,
			RequestOptions::FORM_PARAMS => [
				'token' => $token,
				'token_type_hint' => 'access_token',
			],
		]);
	}

	public function testActiveToken() : void
	{
		$token = $this->getClientCredentialsToken('openid profile')['access_token'];
		$payload = $this->decodeJwtPayload($token);

		$response = $this->introspect($token);
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);

		$this->assertTrue($data['active'] ?? null, 'live token must introspect as active');
		$this->assertSame('access_token', $data['token_type'] ?? null);
		$this->assertSame($this->clientIdentifier(), $data['client_id'] ?? null);
		$this->assertSame($payload['jti'] ?? null, $data['jti'] ?? null);
		$this->assertSame($payload['sub'] ?? null, $data['sub'] ?? null);
		$this->assertNotEmpty($data['exp'] ?? null);
		$this->assertNotEmpty($data['iat'] ?? null);
		$this->assertContains('openid', (array)($data['scope'] ?? []), 'scope is an array of granted scope identifiers');
	}

	public function testRevokedTokenIsInactive() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];
		$payload = $this->decodeJwtPayload($token);
		$this->assertNotEmpty($payload['jti'] ?? null);

		(new AccessTokenRepository())->revokeAccessToken($payload['jti']);

		$response = $this->introspect($token);
		$this->assertHttpStatus(200, $response, 'RFC7662: introspection of an invalid token is still HTTP 200');
		$data = $this->jsonDecode($response);
		$this->assertFalse($data['active'] ?? null, 'revoked token must introspect as active:false');
	}

	public function testMalformedTokenIsInactive() : void
	{
		$response = $this->introspect('this-is-not-a-jwt');
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);
		$this->assertFalse($data['active'] ?? null, 'malformed token must introspect as active:false');
	}

	public function testWrongMethodRejected() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];
		$response = $this->httpClient()->get($this->endpointUrl('/introspect'), [
			RequestOptions::QUERY => ['token' => $token],
			'headers' => ['Authorization' => $this->clientBasicAuthHeader()],
		]);
		$this->assertHttpStatus([400, 404, 405], $response, 'GET /introspect must be rejected (POST-only)');
	}

	public function testNoCredentialsIsInactive() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];

		$response = $this->introspect($token, false);
		$this->assertHttpStatus(200, $response, 'RFC7662: introspection without client auth is still HTTP 200');
		$data = $this->jsonDecode($response);
		$this->assertFalse($data['active'] ?? null, 'introspection without client credentials must be active:false');
	}

	public function testWrongSecretIsInactive() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];
		$badAuth = 'Basic '.base64_encode($this->clientIdentifier().':wrong-secret');

		$response = $this->introspect($token, $badAuth);
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);
		$this->assertFalse($data['active'] ?? null, 'introspection with wrong client secret must be active:false');
	}

	public function testUnknownClientIsInactive() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];
		$badAuth = 'Basic '.base64_encode('no-such-client:whatever');

		$response = $this->introspect($token, $badAuth);
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);
		$this->assertFalse($data['active'] ?? null, 'introspection by an unknown client must be active:false');
	}

	/**
	 * A client authenticated with valid credentials of its own must NOT be able to introspect
	 * another client's token: introspection is restricted to the client the token was issued to.
	 */
	public function testOtherClientCannotIntrospect() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];

		$repo = new ClientRepository();
		$other = new ClientEntity();
		$identifier = 'phpunit-other-'.substr(md5((string)mt_rand()), 0, 8);
		$secret = bin2hex(random_bytes(12));
		$other->setIdentifier($identifier);
		$other->setSecret($secret);
		$other->setName('PHPUnit other client');
		$other->setRedirectUri(static::REDIRECT_URI);
		$other->setScopes([]);
		$other->setGrants(['client_credentials']);
		$repo->persistNewClient($other);

		try {
			$otherAuth = 'Basic '.base64_encode($identifier.':'.$secret);
			$response = $this->introspect($token, $otherAuth);
			$this->assertHttpStatus(200, $response);
			$data = $this->jsonDecode($response);
			$this->assertFalse($data['active'] ?? null, "a client must not be able to introspect another client's token");
		} finally {
			$GLOBALS['egw']->db->delete('egw_openid_clients', ['client_id' => $other->getID()], __LINE__, __FILE__, 'openid');
		}
	}
}
