<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: implicit grant contract test
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
 * GET /authorize response_type=token|id_token|"token id_token" (implicit / hybrid flow)
 *
 * EGroupware\OpenID\Grant\ImplicitGrant is a full copy-and-patch of league's ImplicitGrant (see
 * openid/doc/UPSTREAM-OVERRIDES.md) so it can respond to space-separated response_types containing
 * "id_token" and/or "code" in addition to plain "token" - needed eg. by Guacamole. That is
 * exactly the behavior this test pins down.
 *
 * Contract under test: the client is redirected (302) with the requested token(s) in the URL
 * FRAGMENT (not the query string - implicit/hybrid flows never expose tokens to the server via
 * the query string), matching response_type: "token" -> access_token; "id_token" -> id_token;
 * "token id_token" -> both.
 */
class ImplicitGrantTest extends OpenIDTestBase
{
	protected static array $test_grants = ['implicit'];

	/**
	 * @return array fragment params after '#', decoded
	 */
	protected function authorize(string $response_type, string $state) : array
	{
		$client = $this->httpLogin();
		if ($client === null)
		{
			$this->markTestSkipped('Could not establish an HTTP-authenticated session for '.$this->testAccountLid());
		}
		$this->seedRefreshToken(['openid']);

		$response = $client->get($this->endpointUrl('/authorize'), [
			RequestOptions::ALLOW_REDIRECTS => false,
			RequestOptions::QUERY => [
				'response_type' => $response_type,
				'client_id' => $this->clientIdentifier(),
				'redirect_uri' => self::REDIRECT_URI,
				'scope' => 'openid',
				'state' => $state,
				'nonce' => 'n-'.$state,
			],
		]);
		$this->assertHttpStatus([302, 303], $response,
			"authorize response_type=$response_type must redirect with tokens in the fragment");
		$location = $response->getHeader('Location')[0] ?? '';
		$this->assertStringStartsWith(self::REDIRECT_URI, $location);

		$fragment = parse_url($location, PHP_URL_FRAGMENT);
		$this->assertNotEmpty($fragment, 'implicit/hybrid response must use a URL fragment (#...), not the query string');
		parse_str($fragment, $params);
		$this->assertSame($state, $params['state'] ?? null, 'state must be echoed back unchanged');
		return $params;
	}

	public function testResponseTypeToken() : void
	{
		$params = $this->authorize('token', bin2hex(random_bytes(6)));
		$this->assertNotEmpty($params['access_token'] ?? null, 'access_token missing');
		$this->assertSame('Bearer', $params['token_type'] ?? null);
		$this->assertArrayNotHasKey('id_token', $params, 'response_type=token alone must not include id_token');
	}

	public function testResponseTypeIdToken() : void
	{
		$params = $this->authorize('id_token', bin2hex(random_bytes(6)));
		$this->assertNotEmpty($params['id_token'] ?? null, 'id_token missing');
		$this->assertArrayNotHasKey('access_token', $params, "response_type=id_token alone must not include access_token");
	}

	public function testResponseTypeTokenIdTokenHybrid() : void
	{
		$params = $this->authorize('token id_token', bin2hex(random_bytes(6)));
		$this->assertNotEmpty($params['access_token'] ?? null, 'access_token missing');
		$this->assertNotEmpty($params['id_token'] ?? null, 'id_token missing');
	}

	public function testCodeResponseTypeRejectedForImplicitOnlyClient() : void
	{
		$client = $this->httpLogin();
		if ($client === null)
		{
			$this->markTestSkipped('Could not establish an HTTP-authenticated session for '.$this->testAccountLid());
		}
		// response_type=code alone is the auth-code grant, not implicit - and this client only has
		// the "implicit" grant enabled (no "authorization_code" row in egw_openid_client_grants),
		// so AuthCodeGrant::getClientEntity() rejects it as invalid_client (401).
		$response = $client->get($this->endpointUrl('/authorize'), [
			RequestOptions::ALLOW_REDIRECTS => false,
			RequestOptions::QUERY => [
				'response_type' => 'code',
				'client_id' => $this->clientIdentifier(),
				'redirect_uri' => self::REDIRECT_URI,
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus(401, $response);
	}
}
