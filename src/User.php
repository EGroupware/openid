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

use EGroupware\Api;
use EGroupware\OpenID\Repositories\AccessTokenRepository;
use EGroupware\OpenID\Repositories\ScopeRepository;
use EGroupware\OpenID\Repositories\RefreshTokenRepository;

/**
 * Display tokens of current user under Preferences >> Password & Security
 */
class User
{
	const APP = 'openid';

	/**
	 * Answers preferences_password_security hook
	 *
	 * @param array $data
	 */
	public static function security(array $data)
	{
		unset($data);	// not used, but required by function signature

		Api\Translation::add_app(self::APP);

		return [
			'label' =>	'Revoke Access Tokens',
			'name' => 'openid.access_tokens',
			'prepend' => false,
			'data' => [
				'nm' => [
					'get_rows' => __CLASS__.'::getTokens',
					'no_cat' => true,
					'no_filter' => true,
					'no_filter2' => true,
					'filter_no_lang' => true,
					'order' => 'access_token_updated',
					'sort' => 'DESC',
					'row_id' => 'access_token_id',
					'default_cols' => '!client_id',
					'actions' => self::tokenActions(),
				],
			],
			'sel_options' => [
				'client_status' => ['Disabled', 'Active'],
				'access_token_revoked' => ['Active', 'Revoked'],
				'access_token_scopes' => (new ScopeRepository())->selOptions(),
			],
			'save_callback' => __CLASS__.'::action',
		];
	}

	/**
	 * Callback to run for actions (general on all form posts)
	 *
	 * User password is already checked!
	 *
	 * @param array $content
	 * @return string with success message
	 * @throws Exception on error
	 */
	public static function action(array $content)
	{
		if (is_array($content) && $content['tabs'] === 'openid.access_tokens' && $content['nm']['selected'])
		{
			switch($content['nm']['action'])
			{
				case 'delete':
					$token_repo = new AccessTokenRepository();
					$token_repo->revokeAccessToken(['access_token_id' => $content['nm']['selected']]);
					$refresh_token_repo = new RefreshTokenRepository();
					$refresh_token_repo->revokeRefreshToken(['access_token_id' => $content['nm']['selected']]);
					return (count($content['nm']['selected']) > 1 ?
						count($content['nm']['selected']).' ' : '').
						lang('Access Token revoked.');
			}
		}
		unset($content['nm']['selected'], $content['nm']['action']);
	}

	/**
	 * Query tokens for nextmatch widget
	 *
	 * @param array $query with keys 'start', 'search', 'order', 'sort', 'col_filter'
	 *	For other keys like 'filter', 'cat_id' you have to reimplement this method in a derived class.
	 * @param array &$rows returned rows/competitions
	 * @param array &$readonlys eg. to disable buttons based on acl, not use here, maybe in a derived class
	 * @return int number of rows found
	 */
	public static function getTokens(array $query, array &$rows, array &$readonlys)
	{
		$token_repo = new AccessTokenRepository();
		if (($ret = $token_repo->get_rows($query, $rows, $readonlys)))
		{
			foreach($rows as $key => &$row)
			{
				if (!is_int($key)) continue;

				// boolean does NOT work as key for select-box
				$row['access_token_revoked'] = (string)(int)$row['access_token_revoked'];
				$row['client_status'] = (string)(int)$row['client_status'];

				// dont send token itself to UI
				unset($row['access_token_identifier']);

				// format user-agent as "OS Version\nBrowser Version" prefering auth-code over access-token
				// as for implicit grant auth-code contains real user-agent, access-token container the server
				if (!empty($row['auth_code_user_agent']))
				{
					$row['user_agent'] = Api\Header\UserAgent::osBrowser($row['auth_code_user_agent']);
					$row['user_ip'] = $row['auth_code_ip'];
					$row['user_agent_tooltip'] = Api\Header\UserAgent::osBrowser($row['access_token_user_agent']);
					$row['user_ip_tooltip'] = $row['access_token_ip'];
				}
				else
				{
					$row['user_agent'] = Api\Header\UserAgent::osBrowser($row['access_token_user_agent']);
					$row['user_ip'] = $row['access_token_ip'];
				}
			}
		}
		return $ret;
	}

	/**
	 * Get actions for tokens
	 */
	protected static function tokenActions()
	{
		return [
			'delete' => array(
				'caption' => 'Revoke',
				'allowOnMultiple' => true,
				'confirm' => 'Revoke this token',
			),
		];
	}
}