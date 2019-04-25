<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @subpackage setup
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @link https://github.com/thephpleague/oauth2-server
 */

// give Default group rights for OpenID
$defaultgroup = $GLOBALS['egw_setup']->add_account('Default','Default','Group',False,False);
$GLOBALS['egw_setup']->add_acl('openid','run',$defaultgroup);

// add default scopes
foreach([
	// Without this OpenID Connect cannot work.
	'openid'  => 'Enable OpenID Connect support',
	'basic'   => 'Basic details about you',
	'email'   => 'Your email address',
	'phone'   => 'Your phone number',
	'address' => 'Your address',
	'profile' => 'Your full profile',
	'roles'   => 'Administration rights or regular user',
] as $identifier => $description)
{
	$GLOBALS['egw_setup']->db->insert('egw_openid_scopes', [
		'scope_identifier' => $identifier,
		'scope_description' => $description,
		'scope_created'    => time(),
	], false, __LINE__, __FILE__, 'openid');
}

/* one testclient, should not be enabled on production sites!
foreach([
	'oidcdebugger.com' => [
		'secret'          => password_hash('secret', PASSWORD_BCRYPT),
		'name'            => 'oidcdebugger.com',
		'redirect_uri'    => 'https://oidcdebugger.com/debug',
		'is_confidential' => true,
	]
] as $identifier => $data)
{
	$GLOBALS['egw_setup']->db->insert('egw_openid_clients', [
		'client_identifier' => $identifier,
		'client_name'       => $data['name'],
		'client_secret'     => $data['secret'],
		'client_redirect_uri' => $data['redirect_uri'],
		'client_created'    => time(),
	], false, __LINE__, __FILE__, 'openid');
} */
