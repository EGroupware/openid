<?php
/**
 * EGroupware - Setup
 * https://www.egroupware.org
 * Created by eTemplates DB-Tools written by ralfbecker@outdoor-training.de
 *
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 * @package openid
 * @subpackage setup
 */

$phpgw_baseline = array(
	'egw_openid_scopes' => array(
		'fd' => array(
			'scope_id' => array('type' => 'auto','nullable' => False),
			'scope_identifier' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'scope_description' => array('type' => 'varchar','precision' => '255'),
			'scope_created' => array('type' => 'timestamp','nullable' => False),
			'scope_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('scope_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_clients' => array(
		'fd' => array(
			'client_id' => array('type' => 'auto','nullable' => False),
			'client_name' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'client_identifier' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'client_secret' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'client_redirect_uri' => array('type' => 'ascii','precision' => '255','nullable' => False),
			'client_status' => array('type' => 'bool','nullable' => False,'default' => '1','comment' => '1=active'),
			'client_created' => array('type' => 'timestamp','nullable' => False),
			'client_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp'),
			'client_creator' => array('type' => 'int','meta' => 'user','precision' => '4'),
			'client_modifier' => array('type' => 'int','meta' => 'user','precision' => '4'),
			'client_access_token_ttl' => array('type' => 'varchar','precision' => '16'),
			'client_refresh_token_ttl' => array('type' => 'varchar','precision' => '16')
		),
		'pk' => array('client_id'),
		'fk' => array(),
		'ix' => array('client_identifier','client_status'),
		'uc' => array()
	),
	'egw_openid_client_scopes' => array(
		'fd' => array(
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('client_id','scope_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_client_grants' => array(
		'fd' => array(
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'grant_id' => array('type' => 'int','precision' => '1','nullable' => False)
		),
		'pk' => array('client_id','grant_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_user_grants' => array(
		'fd' => array(
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'grant_id' => array('type' => 'int','precision' => '1','nullable' => False)
		),
		'pk' => array('account_id','grant_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_user_scopes' => array(
		'fd' => array(
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('account_id','scope_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_user_clients' => array(
		'fd' => array(
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('account_id','client_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	),
	'egw_openid_access_tokens' => array(
		'fd' => array(
			'access_token_id' => array('type' => 'auto','nullable' => False),
			'access_token_identifier' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'access_token_expiration' => array('type' => 'timestamp'),
			'access_token_revoked' => array('type' => 'bool','precision' => '1','nullable' => False,'default' => '0'),
			'access_token_type' => array('type' => 'int','precision' => '1','nullable' => False,'default' => '1'),
			'access_token_created' => array('type' => 'timestamp','nullable' => False),
			'access_token_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('access_token_id'),
		'fk' => array(),
		'ix' => array('client_id','account_id','access_token_revoked'),
		'uc' => array()
	),
	'egw_openid_access_token_scopes' => array(
		'fd' => array(
			'access_token_scope_id' => array('type' => 'auto','nullable' => False),
			'access_token_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('access_token_scope_id'),
		'fk' => array(),
		'ix' => array(array('access_token_id','scope_id')),
		'uc' => array()
	),
	'egw_openid_refresh_tokens' => array(
		'fd' => array(
			'refresh_token_id' => array('type' => 'auto','nullable' => False),
			'refresh_token_identifier' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'access_token_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'refresh_token_expiration' => array('type' => 'timestamp'),
			'refresh_token_revoked' => array('type' => 'bool','nullable' => False,'default' => '0'),
			'refresh_token_created' => array('type' => 'timestamp','nullable' => False),
			'refresh_token_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('refresh_token_id'),
		'fk' => array(),
		'ix' => array('access_token_id'),
		'uc' => array()
	),
	'egw_openid_auth_codes' => array(
		'fd' => array(
			'auth_code_id' => array('type' => 'auto','nullable' => False),
			'auth_code_identifier' => array('type' => 'ascii','precision' => '128','nullable' => False),
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'auth_code_expiration' => array('type' => 'timestamp'),
			'auth_code_redirect_uri' => array('type' => 'ascii','precision' => '255','nullable' => False),
			'auth_code_revoked' => array('type' => 'bool','nullable' => False,'default' => '0'),
			'auth_code_created' => array('type' => 'timestamp','nullable' => False),
			'auth_code_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('auth_code_id'),
		'fk' => array(),
		'ix' => array('account_id','client_id'),
		'uc' => array()
	),
	'egw_openid_auth_code_scopes' => array(
		'fd' => array(
			'auth_code_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('auth_code_id','scope_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	)
);
