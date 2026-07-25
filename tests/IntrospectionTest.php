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

/**
 * POST /introspect (RFC7662 OAuth 2.0 Token Introspection)
 *
 * This is a genuinely new feature (no upstream league/oauth2-server support even as of v9, see
 * openid/doc/UPSTREAM-OVERRIDES.md) that MUST be preserved unchanged by the planned rewrite.
 *
 * Contract under test: a client authenticated with Basic auth can introspect a token it holds
 * and get back active/scope/client_id/exp/iat/sub/jti for a live token, and "active":false
 * (still HTTP 200, per RFC7662) for a revoked or malformed token.
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

	protected function introspect(string $token) : \Psr\Http\Message\ResponseInterface
	{
		return $this->httpClient()->post($this->endpointUrl('/introspect'), [
			'headers' => ['Authorization' => $this->clientBasicAuthHeader()],
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

	/**
	 * KNOWN GAP (not asserted as "correct", just documented): Introspector::validateIntrospectionRequest()
	 * only checks the HTTP method is POST - it never actually verifies the client's Basic-auth
	 * credentials against the token's client_id. See openid/doc/UPSTREAM-OVERRIDES.md. This test
	 * intentionally does NOT assert on the Authorization header at all, to avoid encoding that gap
	 * as required behavior; it only pins down that a GET (wrong method) is rejected, which IS
	 * actually enforced.
	 */
	public function testWrongMethodRejected() : void
	{
		$token = $this->getClientCredentialsToken('openid')['access_token'];
		$response = $this->httpClient()->get($this->endpointUrl('/introspect'), [
			RequestOptions::QUERY => ['token' => $token],
			'headers' => ['Authorization' => $this->clientBasicAuthHeader()],
		]);
		$this->assertHttpStatus([400, 404, 405], $response, 'GET /introspect must be rejected (POST-only)');
	}
}
