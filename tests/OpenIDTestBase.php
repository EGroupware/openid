<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: PHPUnit test base class
 *
 * Black-box HTTP contract tests against the real endpoint.php (Slim app), modeled on
 * api/tests/CalDAVTest.php. They assert the documented HTTP/JSON contract of each grant,
 * not internal class shapes, so they keep passing across the planned Slim3->4 /
 * league/oauth2-server 7->9 rewrite (see openid/doc/UPSTREAM-OVERRIDES.md).
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';

use EGroupware\Api;
use EGroupware\Api\LoggedInTest;
use EGroupware\OpenID\Repositories\ClientRepository;
use EGroupware\OpenID\Repositories\GrantRepository;
use EGroupware\OpenID\Entities\ClientEntity;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Cookie\CookieJar;
use Psr\Http\Message\ResponseInterface;

/**
 * Base class for openid/tests/*.
 *
 * Each test class gets its OWN throwaway OAuth2 client (all grants enabled, no scope
 * limit), created in setUpBeforeClass() and removed in tearDownAfterClass(), so tests
 * in different classes cannot interfere with each other's tokens.
 */
abstract class OpenIDTestBase extends LoggedInTest
{
	/**
	 * Redirect URI registered for the test client (never actually reached; auth-code/
	 * implicit tests only need the redirect *response*, they don't follow it).
	 */
	const REDIRECT_URI = 'https://phpunit.example.org/callback';

	/**
	 * Grants enabled for the throwaway test client, keyed by class so parallel test
	 * classes get independent clients.
	 */
	protected static array $client_id = [];
	protected static array $client_identifier = [];
	protected static array $client_secret = [];

	/**
	 * Grants the throwaway client should support; override in a subclass via
	 * static::$test_grants = [...] before setUpBeforeClass() runs, if a test needs fewer.
	 */
	protected static array $test_grants = [
		'client_credentials', 'password', 'authorization_code', 'implicit', 'refresh_token',
	];

	public static function setUpBeforeClass() : void
	{
		parent::setUpBeforeClass();
		static::createTestClient();
	}

	public static function tearDownAfterClass() : void
	{
		static::deleteTestClient();
		parent::tearDownAfterClass();
	}

	/**
	 * Create a throwaway client with all scopes allowed and static::$test_grants enabled.
	 */
	protected static function createTestClient() : void
	{
		$repo = new ClientRepository();

		$client = new ClientEntity();
		$identifier = 'phpunit-'.strtolower(str_replace('\\', '-', static::class)).'-'.substr(md5((string)mt_rand()), 0, 8);
		$secret = bin2hex(random_bytes(12));
		$client->setIdentifier($identifier);
		$client->setSecret($secret);
		$client->setName('PHPUnit '.static::class);
		$client->setRedirectUri(static::REDIRECT_URI);
		$client->setScopes([]);    // no limit --> all scopes allowed
		$client->setGrants(static::$test_grants);

		$repo->persistNewClient($client);

		$class = static::class;
		self::$client_id[$class] = $client->getID();
		self::$client_identifier[$class] = $identifier;
		self::$client_secret[$class] = $secret;
	}

	/**
	 * Remove the throwaway client and any tokens/codes it accumulated during the test run.
	 */
	protected static function deleteTestClient() : void
	{
		$class = static::class;
		if (empty(self::$client_id[$class]) || empty($GLOBALS['egw']->db))
		{
			return;
		}
		$client_id = self::$client_id[$class];
		$db = $GLOBALS['egw']->db;

		$access_token_ids = [];
		foreach($db->select('egw_openid_access_tokens', 'access_token_id',
			['client_id' => $client_id], __LINE__, __FILE__, false, '', 'openid') as $row)
		{
			$access_token_ids[] = $row['access_token_id'];
		}
		$auth_code_ids = [];
		foreach($db->select('egw_openid_auth_codes', 'auth_code_id',
			['client_id' => $client_id], __LINE__, __FILE__, false, '', 'openid') as $row)
		{
			$auth_code_ids[] = $row['auth_code_id'];
		}
		if ($access_token_ids)
		{
			$db->delete('egw_openid_access_token_scopes', ['access_token_id' => $access_token_ids], __LINE__, __FILE__, 'openid');
			$db->delete('egw_openid_refresh_tokens', ['access_token_id' => $access_token_ids], __LINE__, __FILE__, 'openid');
		}
		if ($auth_code_ids)
		{
			$db->delete('egw_openid_auth_code_scopes', ['auth_code_id' => $auth_code_ids], __LINE__, __FILE__, 'openid');
		}
		$db->delete('egw_openid_access_tokens', ['client_id' => $client_id], __LINE__, __FILE__, 'openid');
		$db->delete('egw_openid_auth_codes', ['client_id' => $client_id], __LINE__, __FILE__, 'openid');
		$db->delete('egw_openid_client_scopes', ['client_id' => $client_id], __LINE__, __FILE__, 'openid');
		$db->delete('egw_openid_client_grants', ['client_id' => $client_id], __LINE__, __FILE__, 'openid');
		$db->delete('egw_openid_clients', ['client_id' => $client_id], __LINE__, __FILE__, 'openid');

		unset(self::$client_id[$class], self::$client_identifier[$class], self::$client_secret[$class]);
	}

	protected function clientIdentifier() : string
	{
		return self::$client_identifier[static::class];
	}

	protected function clientSecret() : string
	{
		return self::$client_secret[static::class];
	}

	protected function clientDbId() : int
	{
		return self::$client_id[static::class];
	}

	/**
	 * account_id/lid of the demo user tests run as (from doc/phpunit.xml)
	 */
	protected function testAccountId() : int
	{
		return $GLOBALS['egw_info']['user']['account_id'];
	}

	protected function testAccountLid() : string
	{
		return $GLOBALS['EGW_USER'];
	}

	/**
	 * EGW_URL environment/phpunit-var, eg. "http://localhost/egroupware" (no trailing slash)
	 */
	protected function egwUrl() : string
	{
		$egw_url = getenv('EGW_URL') ?: ($_ENV['EGW_URL'] ?? null) ?: ($GLOBALS['EGW_URL'] ?? null) ?:
			'http://localhost/egroupware';
		return rtrim($egw_url, '/');
	}

	/**
	 * Base URL of the openid Slim app, eg. "http://localhost/egroupware/openid/endpoint.php"
	 */
	protected function endpointUrl(string $path='') : string
	{
		return $this->egwUrl().'/openid/endpoint.php'.$path;
	}

	/**
	 * OpenID Connect Discovery document lives at the *server root*, not under /egroupware/
	 *
	 * @see well-known-configuration.php
	 */
	protected function discoveryUrl() : string
	{
		$parts = parse_url($this->egwUrl());
		$root = ($parts['scheme'] ?? 'http').'://'.($parts['host'] ?? 'localhost').
			(isset($parts['port']) ? ':'.$parts['port'] : '');
		return $root.'/.well-known/openid-configuration';
	}

	/**
	 * Default Guzzle options: do not throw on 4xx/5xx, no automatic redirects (we assert on them), bounded timeouts.
	 */
	protected array $client_options = [
		RequestOptions::HTTP_ERRORS => false,
		RequestOptions::ALLOW_REDIRECTS => false,
		RequestOptions::CONNECT_TIMEOUT => 5,
		RequestOptions::TIMEOUT => 10,
	];

	/**
	 * Anonymous Guzzle client, no cookies/auth - that's all endpoint.php needs except /authorize.
	 */
	protected function httpClient(array $options=[]) : Client
	{
		return new Client(array_merge($this->client_options, $options));
	}

	/**
	 * HTTP Basic auth header value for the test client (used by /introspect)
	 */
	protected function clientBasicAuthHeader() : string
	{
		return 'Basic '.base64_encode($this->clientIdentifier().':'.$this->clientSecret());
	}

	/**
	 * Log in as the phpunit demo user via a real HTTP POST to login.php (like a browser),
	 * returning a Guzzle client with the resulting session cookie attached - needed for
	 * /authorize which requires a real EGroupware session.
	 *
	 * @return Client|null null if login failed (eg. account expired in this environment);
	 *                      callers should markTestSkipped() in that case.
	 */
	protected function httpLogin(?string $user=null, ?string $password=null) : ?Client
	{
		$user = $user ?? $this->testAccountLid();
		$password = $password ?? $GLOBALS['EGW_PASSWORD'];

		$jar = new CookieJar();
		$client = new Client(array_merge($this->client_options, [
			RequestOptions::COOKIES => $jar,
			RequestOptions::ALLOW_REDIRECTS => true,
		]));
		$response = $client->post($this->egwUrl().'/login.php', [
			RequestOptions::FORM_PARAMS => [
				'login' => $user,
				'passwd' => $password,
				'passwd_type' => 'text',
				'submitit' => 'Login',
			],
		]);
		$body = (string)$response->getBody();
		if ($response->getStatusCode() !== 200 || !$jar->getCookieByName('sessionid') ||
			str_contains($body, 'name="passwd"') || str_contains($body, '[Login]'))
		{
			return null;
		}
		return $client;
	}

	/**
	 * Assert an HTTP status (or one of several), including the response body in the failure message.
	 *
	 * @param int|int[] $expected
	 */
	protected function assertHttpStatus($expected, ResponseInterface $response, string $message='') : void
	{
		$expected = (array)$expected;
		$this->assertContains($response->getStatusCode(), $expected,
			($message !== '' ? $message.': ' : '').
			"Expected HTTP ".implode(' or ', $expected)." but got {$response->getStatusCode()}: ".
			substr((string)$response->getBody(), 0, 500));
	}

	/**
	 * Decode a JSON response body into an array (empty array if not valid JSON).
	 */
	protected function jsonDecode(ResponseInterface $response) : array
	{
		$data = json_decode((string)$response->getBody(), true);
		return is_array($data) ? $data : [];
	}

	/**
	 * Request an access-token via the client_credentials grant (the simplest, non-interactive
	 * grant), for use as a fixture by tests that just need *some* valid token/client pairing.
	 *
	 * @return array decoded JSON token response
	 */
	protected function getClientCredentialsToken(string $scope='openid') : array
	{
		$response = $this->httpClient()->post($this->endpointUrl('/access_token'), [
			RequestOptions::FORM_PARAMS => [
				'grant_type' => 'client_credentials',
				'client_id' => $this->clientIdentifier(),
				'client_secret' => $this->clientSecret(),
				'scope' => $scope,
			],
		]);
		$this->assertHttpStatus(200, $response, 'client_credentials fixture token request failed');
		return $this->jsonDecode($response);
	}

	/**
	 * Seed a pre-existing, non-revoked refresh-token (+ its access-token) for the test client
	 * and given user/scopes directly in the DB.
	 *
	 * Authorize::requireApproval() skips the interactive consent screen when the user already
	 * has a valid refresh-token for the client covering the requested scopes - so auth-code and
	 * implicit grant tests can use this to get a fully automated, non-interactive /authorize
	 * request instead of having to drive the Etemplate consent dialog over HTTP.
	 *
	 * @param string[] $scope_identifiers eg. ['openid']
	 */
	protected function seedRefreshToken(array $scope_identifiers, ?int $account_id=null) : void
	{
		$account_id = $account_id ?? $this->testAccountId();
		$db = $GLOBALS['egw']->db;

		$scope_ids = [];
		foreach($db->select('egw_openid_scopes', 'scope_id', ['scope_identifier' => $scope_identifiers],
			__LINE__, __FILE__, false, '', 'openid') as $row)
		{
			$scope_ids[] = $row['scope_id'];
		}
		$this->assertNotEmpty($scope_ids, 'Unknown scope(s) in '.implode(',', $scope_identifiers));

		$now = time();
		$db->insert('egw_openid_access_tokens', [
			'access_token_identifier' => bin2hex(random_bytes(20)),
			'client_id' => $this->clientDbId(),
			'account_id' => $account_id,
			'access_token_expiration' => $now + 3600,
			'access_token_created' => $now,
		], false, __LINE__, __FILE__, 'openid');
		$access_token_id = $db->get_last_insert_id('egw_openid_access_tokens', 'access_token_id');

		foreach($scope_ids as $scope_id)
		{
			$db->insert('egw_openid_access_token_scopes', [
				'access_token_id' => $access_token_id,
				'scope_id' => $scope_id,
			], false, __LINE__, __FILE__, 'openid');
		}

		$db->insert('egw_openid_refresh_tokens', [
			'refresh_token_identifier' => bin2hex(random_bytes(20)),
			'access_token_id' => $access_token_id,
			'refresh_token_expiration' => $now + 86400,
			'refresh_token_created' => $now,
		], false, __LINE__, __FILE__, 'openid');
	}
}
