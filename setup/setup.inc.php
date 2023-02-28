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

use EGroupware\OpenID;

$setup_info['openid']['name']    = 'openid';
$setup_info['openid']['title']   = 'OpenID';
$setup_info['openid']['version'] = '23.1';
$setup_info['openid']['app_order'] = 1;
$setup_info['openid']['tables']  = array('egw_openid_scopes','egw_openid_clients','egw_openid_client_scopes','egw_openid_client_grants','egw_openid_user_grants','egw_openid_user_scopes','egw_openid_user_clients','egw_openid_access_tokens','egw_openid_access_token_scopes','egw_openid_refresh_tokens','egw_openid_auth_codes','egw_openid_auth_code_scopes');
$setup_info['openid']['enable']  = 2;
$setup_info['openid']['autoinstall'] = true;	// install automatically on update

$setup_info['openid']['author'] =
$setup_info['openid']['maintainer'] = [
	'name' => 'Ralf Becker',
	'email' => 'rb@egroupware.org',
	'url'   => 'https://www.egroupware.org',
];
$setup_info['openid']['license']  = 'GPL2+';
$setup_info['openid']['description'] = 'OpenID Connect and OAuth server for EGroupware';

// The hooks this app includes, needed for hooks registration
$setup_info['openid']['hooks']['admin']   = OpenID\Ui::class.'::menu';
$setup_info['openid']['hooks']['sidebox']   = OpenID\Ui::class.'::menu';
$setup_info['openid']['hooks']['preferences_security'] = OpenID\User::class.'::security';
$setup_info['openid']['hooks']['csp-frame-src'] = OpenID\Hooks::class.'::csp_frame_src';

$setup_info['openid']['depends'][] = [
	'appname' => 'api',
	'versions' => ['23.1'],
];