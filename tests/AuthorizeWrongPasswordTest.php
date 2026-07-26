<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: wrong-password-on-login regression test
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/OpenIDTestBase.php';

use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\RequestOptions;

/**
 * README "Open tasks": "wrong password on login looses oauth request in session and therefore
 * fails after correct password was entered".
 *
 * Root cause is NOT session data loss: Api\Session::create() returns false (rejecting a bad
 * password) *before* it ever touches the session, and Api\Cache::setSession()'s data (backed by
 * plain $_SESSION) survives the session_regenerate_id(true) call a *successful* login does later.
 *
 * The actual bug is in login.php: the login form's action URL carries "phpgw_forward" (and other
 * "phpgw_*" params) as a query string (see api/templates/default/login.tpl "{login_url}"), which
 * PHP populates into $_GET regardless of request method - but the redirect issued on a *rejected*
 * login (`Egw::redirect_link('/login.php?cd=' . $reason)`) rebuilds the URL from scratch and drops
 * every "phpgw_*" param. The re-rendered login form's new action URL then has no phpgw_forward, so
 * a *subsequent, correct* login falls through to the default "/index.php" instead of back to the
 * pending /openid/endpoint.php/authorize request - the OAuth client never gets its redirect.
 *
 * This test drives the real login.php the way a browser would (shared cookie jar, no auto
 * redirects, reusing the query string of each redirect's Location as the next request's URL,
 * exactly like resubmitting the re-rendered login form would), so it fails the same way a real
 * wrong-password retry does.
 */
class AuthorizeWrongPasswordTest extends OpenIDTestBase
{
	// refresh_token must also be enabled, so seedRefreshToken()'s fixture lets
	// Authorize::requireApproval() skip the interactive consent screen (see AuthCodeGrantTest)
	protected static array $test_grants = ['authorization_code', 'refresh_token'];

	/**
	 * Location headers here can be scheme-relative or host-relative; Guzzle needs an absolute URI.
	 */
	protected function absoluteUrl(string $location) : string
	{
		if (preg_match('#^https?://#i', $location))
		{
			return $location;
		}
		$parts = parse_url($this->egwUrl());
		$root = ($parts['scheme'] ?? 'http').'://'.($parts['host'] ?? 'localhost').
			(isset($parts['port']) ? ':'.$parts['port'] : '');
		return $root.$location;
	}

	public function testWrongPasswordThenCorrectPasswordCompletesAuthorization() : void
	{
		$this->seedRefreshToken(['openid']);

		$client = $this->httpClient(['cookies' => new CookieJar()]);

		// Step 1: anonymous /authorize creates an anon session and redirects to login.php,
		// carrying phpgw_forward back to this same /authorize request.
		$authorize = $client->get($this->endpointUrl('/authorize'), [
			RequestOptions::QUERY => [
				'response_type' => 'code',
				'client_id' => $this->clientIdentifier(),
				'redirect_uri' => self::REDIRECT_URI,
				'scope' => 'openid',
			],
		]);
		$this->assertHttpStatus([302, 303], $authorize, 'anonymous /authorize must redirect to login.php');
		$login_location = $authorize->getHeader('Location')[0] ?? '';
		$this->assertStringContainsString('/login.php', $login_location);
		parse_str((string)parse_url($login_location, PHP_URL_QUERY), $login_params);
		$this->assertNotEmpty($login_params['phpgw_forward'] ?? null,
			'login redirect must carry phpgw_forward back to the pending /authorize request');

		// Step 2: submit a WRONG password to exactly the URL (incl. query) the login screen's
		// <form action> would have used - a real browser has nothing else to submit to.
		$wrong_login = $client->post($this->egwUrl().'/login.php?'.http_build_query($login_params), [
			RequestOptions::FORM_PARAMS => [
				'login' => $this->testAccountLid(),
				'passwd' => 'definitely-the-wrong-password',
				'passwd_type' => 'text',
				'submitit' => 'Login',
			],
		]);
		$this->assertHttpStatus([302, 303], $wrong_login, 'a rejected login must still redirect back to the login screen');
		$retry_location = $wrong_login->getHeader('Location')[0] ?? '';
		parse_str((string)parse_url($retry_location, PHP_URL_QUERY), $retry_params);
		$this->assertSame($login_params['phpgw_forward'], $retry_params['phpgw_forward'] ?? null,
			'phpgw_forward must survive a rejected login attempt, so a subsequent correct login still returns to /authorize');

		// Step 3: submit the CORRECT password to the re-rendered login screen's action URL
		// (exactly $retry_params - a real browser only has what that page's form gave it).
		$correct_login = $client->post($this->egwUrl().'/login.php?'.http_build_query($retry_params), [
			RequestOptions::FORM_PARAMS => [
				'login' => $this->testAccountLid(),
				'passwd' => $GLOBALS['EGW_PASSWORD'],
				'passwd_type' => 'text',
				'submitit' => 'Login',
			],
		]);
		$this->assertHttpStatus([302, 303], $correct_login);
		$back_to_authorize = $correct_login->getHeader('Location')[0] ?? '';
		$this->assertStringContainsString('/openid/endpoint.php/authorize', $back_to_authorize,
			'a correct login after a wrong attempt must return to the pending /authorize request, not the default desktop');

		// Step 4: following that redirect completes the OAuth flow (consent pre-approved via the
		// seeded refresh-token), landing back at the client's redirect_uri with an auth code.
		$final = $client->get($this->absoluteUrl($back_to_authorize));
		$this->assertHttpStatus([302, 303], $final);
		$code_location = $final->getHeader('Location')[0] ?? '';
		$this->assertStringStartsWith(self::REDIRECT_URI, $code_location,
			'must redirect to the client redirect_uri with an auth code, completing the OAuth flow');
		parse_str((string)parse_url($code_location, PHP_URL_QUERY), $code_params);
		$this->assertNotEmpty($code_params['code'] ?? null, 'auth code missing after completed login');
	}
}
