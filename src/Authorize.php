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
	 * Enable or disable debug-messages to error_log
	 */
	const DEBUG = false;

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
		if (self::DEBUG) error_log(__METHOD__."(...) anon_session=".self::$anon_session.", user.account_lid={$GLOBALS['egw_info']['user']['account_lid']}");
		// check if we have stored authRequest, restore it
		if (self::$anon_session || !$this->authRequest || isset($_GET['client_id']))
		{
			// Validate the HTTP request and return an AuthorizationRequest object.
			// The auth request object can be serialized into a user's session
			$this->authRequest = $server->validateAuthorizationRequest($request);

			// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
			Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

			// if we have no user-session --> redirect to login
			if (self::$anon_session || $GLOBALS['egw_info']['user']['account_lid'] === 'anonymous')
			{
				if (self::DEBUG) error_log(__METHOD__."(...) no user session --> redirect to login");
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
			if (self::DEBUG) error_log(__METHOD__."(...) ask for user approval");
			// Once the user has logged in set the user on the AuthorizationRequest
			$this->authRequest->setUser(new Entities\UserEntity($GLOBALS['egw_info']['user']['account_id']));

			// if client is managed as EGroupware app, check if user has run-rights for the app
			if (!$this->authRequest->getClient()->currentUserAllowed())
			{
				$this->authRequest->setAuthorizationApproved(false);
			}
			// check if we need (a new) approval by the user
			elseif ($this->requireApproval())
			{
				// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
				Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

				// show user page with requested permissions, so he can approve or deny
				$this->approve();	// does NOT return
			}
			else
			{
				$this->authRequest->setAuthorizationApproved(true);
			}
		}
		if (self::DEBUG) error_log(__METHOD__."(...) user approval or denied --> return to openid flow");
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
		if (self::DEBUG) error_log(__METHOD__."() start");
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

		if (self::DEBUG) error_log(__METHOD__."() calling tpl->exec(..., ".json_encode($content).", ".json_encode($sel_options).")");
		$tpl->exec('api.'.self::class.'.submit', $content, $sel_options,
			null, null, 2);	// 2 = popup, not full UI
		if (self::DEBUG) error_log(__METHOD__."() after tpl->exec --> exiting now to send approval form to user");
		exit;
	}

	/**
	 * eT2 callback updating authRequest with users approval/denial and redirects back to caller URL
	 */
	public function submit(array $content)
	{
		if (self::DEBUG) error_log(__METHOD__."(".json_encode($content).")");
		$this->authRequest->setAuthorizationApproved(!empty($content['button']['approve']) ? true : null);

		// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
		Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));

		if (self::DEBUG) error_log(__METHOD__."() approved=".json_encode(!empty($content['button']['approve']) ? true : null)." --> redirecting to $this->url?cd=no");
		Api\Framework::redirect_link($this->url.'?cd=no');
	}

	/**
	 * Check if the request requires (a new) approval
	 *
	 * We check if the user still have a valid refresh token for the client.
	 * If that is the case, the client could have just used that, but not all clients do :(
	 *
	 * @return boolean
	 */
	protected function requireApproval()
	{
		// if OAuth client is managed as EGroupware we do NOT require (explicit) user consent
		if ($this->authRequest->getClient()->getApplicationName() && $this->authRequest->getClient()->currentUserAllowed())
		{
			return false;
		}
		$refreshtoken_repo = new Repositories\RefreshTokenRepository();

		$refresh_token = $refreshtoken_repo->findToken($this->authRequest->getClient(),
			$this->authRequest->getUser());

		if (self::DEBUG) error_log(__METHOD__."() client=".$this->authRequest->getClient()->getIdentifier().", user=".$this->authRequest->getUser()->getIdentifier().", refreshToken=".array2string($refresh_token));

		if ($refresh_token)
		{
			// check if refresh token contains the requested scopes
			$scopes = $refresh_token->getAccessToken()->getScopes();
			foreach($this->authRequest->getScopes() as $required)
			{
				if (!in_array($required, $scopes))
				{
					if (self::DEBUG) error_log(__METHOD__."() return true (missing scope ".$required->getIdentifier().')');
					return true;
				}
			}
		}
		return !$refresh_token;
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
		self::$anon_session = !empty($_COOKIE['last_loginid']) &&
			strpos($_COOKIE['last_loginid'], 'anonymous@') !== 0 ?
			$_COOKIE['last_loginid'] : true;

		// create session without checking auth: create(..., false, false)
		return $GLOBALS['egw']->session->create('anonymous@'.$GLOBALS['egw_info']['user']['domain'],
			'', 'text', false, false);
	}
}
