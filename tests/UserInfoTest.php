<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: /userinfo contract test
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
 * GET /userinfo with "Authorization: Bearer <access_token>"
 *
 * Contract under test: claims returned are gated by the scopes the access_token was actually
 * issued with (least-privilege) - requesting only "openid" must NOT leak profile/email/phone/
 * roles/groups claims, while requesting the matching scope must return them. Also covers the
 * EGroupware-specific "roles", "groups" and "email_aliases" scopes/claims (not in upstream OIDC).
 * Pass criteria: HTTP 200 in all cases; claim presence exactly matches the requested scope; a
 * request with no/invalid Bearer token is rejected with HTTP 401.
 */
class UserInfoTest extends OpenIDTestBase
{
	protected static array $test_grants = ['password'];

	protected function tokenWithScope(string $scope) : string
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'password',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'username' => $this->testAccountLid(),
				'password' => $GLOBALS['EGW_PASSWORD'],
				'scope' => $scope,
			],
		]);
		$this->assertHttpStatus(200, $response, "fixture token request for scope '$scope' failed");
		$data = $this->jsonDecode($response);
		$this->assertNotEmpty($data['access_token'] ?? null);
		return $data['access_token'];
	}

	protected function userinfo(string $access_token)
	{
		return $this->httpClient()->get($this->endpointUrl('/userinfo'), [
			'headers' => ['Authorization' => 'Bearer '.$access_token],
		]);
	}

	public function testMinimalScopeHasSubButNoProfileClaims() : void
	{
		$response = $this->userinfo($this->tokenWithScope('openid'));
		$this->assertHttpStatus(200, $response);
		$data = $this->jsonDecode($response);

		$this->assertArrayHasKey('sub', $data);
		foreach(['name', 'email', 'phone_number', 'address', 'roles', 'groups', 'email_aliases'] as $leaked)
		{
			$this->assertArrayNotHasKey($leaked, $data,
				"scope 'openid' alone must not leak claim '$leaked'");
		}
	}

	public function testProfileScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid profile')));
		foreach(['name', 'family_name', 'given_name', 'preferred_username', 'zoneinfo', 'locale'] as $claim)
		{
			$this->assertArrayHasKey($claim, $data, "profile scope must include claim '$claim'");
		}
		$this->assertArrayNotHasKey('email', $data, "'profile' scope must not include 'email' claim");
	}

	public function testEmailScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid email')));
		$this->assertArrayHasKey('email', $data);
		$this->assertArrayHasKey('email_verified', $data);
	}

	public function testPhoneScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid phone')));
		$this->assertArrayHasKey('phone_number', $data);
		$this->assertArrayHasKey('phone_number_verified', $data);
	}

	public function testAddressScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid address')));
		$this->assertArrayHasKey('address', $data);
		$this->assertIsArray($data['address']);
	}

	public function testRolesScopeIncludesUserRole() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid roles')));
		$this->assertArrayHasKey('roles', $data);
		$this->assertContains('user', $data['roles'], 'every authenticated user must have the "user" role');
	}

	public function testGroupsScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid groups')));
		$this->assertArrayHasKey('groups', $data);
		$this->assertIsArray($data['groups']);
	}

	public function testEmailAliasesScope() : void
	{
		$data = $this->jsonDecode($this->userinfo($this->tokenWithScope('openid email_aliases')));
		$this->assertArrayHasKey('email_aliases', $data);
		$this->assertIsArray($data['email_aliases']);
	}

	public function testMissingBearerTokenRejected() : void
	{
		$response = $this->httpClient()->get($this->endpointUrl('/userinfo'));
		$this->assertHttpStatus(401, $response, 'userinfo without a Bearer token must be rejected');
	}

	public function testInvalidBearerTokenRejected() : void
	{
		$response = $this->httpClient()->get($this->endpointUrl('/userinfo'), [
			'headers' => ['Authorization' => 'Bearer not-a-real-token'],
		]);
		$this->assertHttpStatus(401, $response, 'userinfo with a bogus Bearer token must be rejected');
	}
}
