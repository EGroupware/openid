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

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use EGroupware\OpenID\ScopeRepository;
use EGroupware\Api;

/**
 * Display UI to let user authorize a request
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
	 * @param AuthorizationRequest $authRequest =null
	 * @param string $url =null
	 */
	public function __construct(AuthorizationRequest $authRequest=null, $url=null)
	{
		$this->authRequest = $authRequest;
		$this->url = $url;
	}

	/**
	 * Display form to use to approve scopes given by client
	 *
	 * Does NOT return
	 */
	public function approve()
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
		$sel_options = [
			'scopes' => array_map(function($scope)
			{
				return $scope['description'];
			}, Repositories\ScopeRepository::getScopes()),
		];
		$_GET['cd'] = 'no';	// hack to stop framework redirect
		$GLOBALS['egw_info']['flags']['js_link_registry'] = true;	// as we have no regular framework

		$tpl->exec('api.'.self::class.'.submit', $content, $sel_options, null, [
			'url' => $this->url,
			'authRequest' => serialize($this->authRequest),
		], 2);	// 2 = popup, not full UI
		exit;
	}

	/**
	 * Updates authRequest with users approval/denial and redirects back to caller URL
	 */
	public function submit(array $content)
	{
		require_once __DIR__.'/../vendor/autoload.php';

		$this->authRequest = unserialize($content['authRequest']);
		$this->authRequest->setAuthorizationApproved(!empty($content['button']['approve']) ? true : null);

		// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
		Api\Cache::setSession('openid', 'authRequest', serialize($this->authRequest));
		Api\Framework::redirect_link($content['url']);
	}
}
