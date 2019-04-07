<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @link https://github.com/thephpleague/oauth2-server
 */

namespace EGroupware\OpenID;

// until #925 is merged: use League\OAuth2\Server\AuthorizationServer;
use EGroupware\OpenId\AuthorizationServer;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use EGroupware\Api;

/**
 * Display UI to let user login, if not already and authorize an OAuth request
 *
 * The initial auth-request is kept in the session, while we need to redirect
 * multiple times to let user login or authorize the request.
 */
class Authorize
{
	/**
	 * menuaction callable methods
	 *
	 * @var boolean[]
	 */
	public $public_functions = [
		'approve' => true,
	];

	/**
	 * Username or true if we had to create an anonymous session
	 *
	 * User is from last_loginid cookie before creating the anonymous session
	 *
	 * @var string|boolean
	 */
	protected static $anon_session = false;

	/**
	 * Request we need to autorize
	 *
	 * @var AuthorizationRequest
	 */
	protected $authRequest;

	/**
	 * Calling (relative) URL we redirect to after user approved or denied
	 *
	 * @var string
	 */
	protected $url;

	/**
	 * Constructor
	 *
	 * @param string $url =null
	 */
	public function __construct($url=null)
	{
		if (empty($url))
		{
			$this->url = Api\Cache::getSession('openid', 'url');
		}
		else
		{
			Api\Cache::setSession('openid', 'url', $this->url=$url);
		}

		require_once __DIR__.'/../vendor/autoload.php';

		if (($ar = Api\Cache::getSession('openid', 'authRequest')))
		{
			$this->authRequest = unserialize($ar);
		}
	}

	/**
	 * Validate authorization
	 */
	public function validate(AuthorizationServer $server, ServerRequestInterface $request)
	{
		// check if we have stored authRequest, restore it
		if (self::$anon_session || !$this->authRequest || isset($_GET['client_id']))
		{
			// Validate the HTTP request and return an AuthorizationRequest object.
			// The auth request object can be serialized into a user's session
			$this->authRequest = $server->validateAuthorizationRequest($request);

			// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
			Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

			// if we have no user-session --> redirect to login
			if (self::$anon_session)
			{
				// if we had a "last_loginid" cookie, before creating the anon session, restore it
				if (self::$anon_session !== true)
				{
					Api\Session::egw_setcookie('last_loginid', self::$anon_session , Api\DateTime::to('+2weeks', 'ts'));
				}
				Api\Framework::redirect_link('/login.php', [
					'phpgw_forward' => $this->url.'?cd=no',
					'cd' => lang('Login to authorize %1', $this->authRequest->getClient()->getName())
				]);
			}
		}

		if ($this->authRequest->isAuthorizationApproved() === false)
		{
			// Once the user has logged in set the user on the AuthorizationRequest
			$this->authRequest->setUser(new Entities\UserEntity($GLOBALS['egw_info']['user']['account_id']));

			// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
			Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

			// show user page with requested permissions, so he can approve or deny
			$this->approve();	// does NOT return
		}
		// remove it for the next request
		Api\Cache::unsetSession('openid', 'authRequest');

		return $this->authRequest;
	}

	/**
	 * Display form to use to approve scopes given by client
	 *
	 * Does NOT return
	 */
	protected function approve()
	{
		$tpl = new Api\Etemplate('openid.authorize');
		$content = [
			'client_id' => $this->authRequest->getClient()->getIdentifier(),
			'client' => $this->authRequest->getClient()->getName(),
			'scopes' => array_map(function($scope)
			{
				return $scope->getIdentifier();
			}, $this->authRequest->getScopes()),
		];
		$scopeRespository = new Repositories\ScopeRepository();
		$sel_options = [
			'scopes' => array_map(function($scope)
			{
				return $scope['description'];
			}, $scopeRespository->getScopes()),
		];
		$_GET['cd'] = 'no';	// hack to stop framework redirect
		$GLOBALS['egw_info']['flags']['js_link_registry'] = true;	// as we have no regular framework

		$tpl->exec('api.'.self::class.'.submit', $content, $sel_options,
			null, null, 2);	// 2 = popup, not full UI
		exit;
	}

	/**
	 * eT2 callback updating authRequest with users approval/denial and redirects back to caller URL
	 */
	public function submit(array $content)
	{
		$this->authRequest->setAuthorizationApproved(!empty($content['button']['approve']) ? true : null);

		// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
		Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

		Api\Framework::redirect_link($this->url.'?cd=no');
	}

	/**
	 * Callback to create anonymous session
	 *
	 * Only called, if there is not already a user session.
	 *
	 * @param array|null $anon_account
	 * @return string|boolean session-id from Api\Session::create, or true to automatic create session
	 */
	public static function anon_session(&$anon_account)
	{
		$anon_account = null;

		// we dont have a session, but want to continue
		self::$anon_session = !empty($_COOKIE['last_loginid']) ? $_COOKIE['last_loginid'] : true;

		// create session without checking auth: create(..., false, false)
		return $GLOBALS['egw']->session->create('anonymous@'.$GLOBALS['egw_info']['user']['domain'],
			'', 'text', false, false);
	}
}
