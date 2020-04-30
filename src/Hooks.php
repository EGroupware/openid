<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID;

/**
 * Display tokens of current user under Preferences >> Password & Security
 */
class Hooks
{
	const APP = 'openid';

	/**
	 * Add CSP frame-src for apps running in iframe
	 *
	 * @param array $data
	 * @return array with frame sources
	 */
	public static function csp_frame_src(array $data)
	{
		// add CSP frame-src for apps which are just iframes
		$srcs = [];
		foreach($GLOBALS['egw_info']['user']['apps'] ?: [] as $app => $data)
		{
			if ($GLOBALS['egw_info']['apps'][$app]['status'] == 1 && !empty($data['index']) &&
				preg_match('|^(https?://[^/]+)|', $data['index'], $matches))
			{
				$srcs[] = $matches[1];
			}
		}
		return $srcs;
	}
}
