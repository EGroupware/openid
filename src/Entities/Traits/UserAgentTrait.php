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

namespace EGroupware\OpenID\Entities\Traits;

use EGroupware\Api\Session;

/**
 * Trait for managing user-agent and ip address of user
 */
trait UserAgentTrait
{
	/**
	 * User-agent / browser of user
	 *
	 * @var string
	 */
	protected $user_agent;

	/**
	 * IP adress of user
	 *
	 * @var string
	 */
	protected $ip;

	/**
	 * Set user-agent
	 *
	 * @param string|self $user_agent =null default user-agent from headers
	 */
	public function setUserAgent($user_agent=null)
	{
		if (is_object($user_agent) && in_array(self::class, class_uses($user_agent)))
		{
			$this->user_agent = $user_agent->getUserAgent();
		}
		else
		{
			$this->user_agent = empty($user_agent) ? $_SERVER['HTTP_USER_AGENT'] : $user_agent;
		}
	}

	/**
	 * Get user-agent
	 *
	 * @return int
	 */
	public function getUserAgent()
	{
		return $this->user_agent;
	}

	/**
	 * Set IP address
	 *
	 * @param string|self $ip =null default ip from heders / Api\Session class
	 */
	public function setIP($ip=null)
	{
		if (is_object($ip) && in_array(self::class, class_uses($ip)))
		{
			$this->ip = $ip->getIP();
		}
		else
		{
			$this->ip = empty($ip) ? Session::getuser_ip() : $ip;
		}
	}

	/**
	 * Get IP address
	 *
	 * @return int
	 */
	public function getIP()
	{
		return $this->ip;
	}
}