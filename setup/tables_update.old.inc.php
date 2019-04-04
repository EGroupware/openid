<?php
/**
 * eGroupWare - Setup
 * http://www.egroupware.org
 * Created by eTemplates DB-Tools written by ralfbecker@outdoor-training.de
 *
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 * @package openid
 * @subpackage setup
 * @version $Id$
 */

function openid_upgrade0_1()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_access_token_scopes',array(
		'fd' => array(
			'access_token_scope_id' => array('type' => 'auto','nullable' => False),
			'access_token_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('access_token_scope_id'),
		'fk' => array(),
		'ix' => array(array('access_token_id','scope_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.002';
}


function openid_upgrade0_1_002()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_refresh_tokens',array(
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
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.003';
}


function openid_upgrade0_1_003()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_auth_codes',array(
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
		'ix' => array(),
		'uc' => array('account_id','client_id')
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.004';
}


function openid_upgrade0_1_004()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_auth_code_scopes',array(
		'fd' => array(
			'auth_code_scope_id' => array('type' => 'auto','nullable' => False),
			'auth_code_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('auth_code_scope_id'),
		'fk' => array(),
		'ix' => array(array('auth_code_id','scope_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.005';
}


function openid_upgrade0_1_005()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_scopes',array(
		'fd' => array(
			'scope_id' => array('type' => 'auto','nullable' => False),
			'scope_identifier' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'scope_description' => array('type' => 'varchar','precision' => '255'),
			'scope_created' => array('type' => 'timestamp','nullable' => False),
			'scope_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('scope_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.006';
}


function openid_upgrade0_1_006()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_grants',array(
		'fd' => array(
			'grant_id' => array('type' => 'auto','nullable' => False),
			'grant_identifier' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'grant_description' => array('type' => 'varchar','precision' => '255'),
			'grant_created' => array('type' => 'timestamp','nullable' => False),
			'grant_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp')
		),
		'pk' => array('grant_id'),
		'fk' => array(),
		'ix' => array(),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.007';
}


function openid_upgrade0_1_007()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_grant_scopes',array(
		'fd' => array(
			'grant_scope_id' => array('type' => 'auto','nullable' => False),
			'grant_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('grant_scope_id'),
		'fk' => array(),
		'ix' => array(array('grant_id','scope_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.008';
}


function openid_upgrade0_1_008()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_clients',array(
		'fd' => array(
			'client_id' => array('type' => 'auto','nullable' => False),
			'client_name' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'client_identifier' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'client_secret' => array('type' => 'varchar','precision' => '128','nullable' => False),
			'client_redirect_uri' => array('type' => 'ascii','precision' => '255','nullable' => False),
			'client_status' => array('type' => 'bool','nullable' => False,'default' => '1','comment' => '1=active'),
			'client_created' => array('type' => 'timestamp','nullable' => False),
			'client_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestampt')
		),
		'pk' => array('client_id'),
		'fk' => array(),
		'ix' => array('client_identifier','client_status'),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.009';
}


function openid_upgrade0_1_009()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_client_scopes',array(
		'fd' => array(
			'client_scope_id' => array('type' => 'auto','nullable' => False),
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('client_scope_id'),
		'fk' => array(),
		'ix' => array(array('client_id','scope_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.010';
}


function openid_upgrade0_1_010()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_client_grants',array(
		'fd' => array(
			'client_grant_id' => array('type' => 'auto','nullable' => False),
			'client_id' => array('type' => 'int','precision' => '4','nullable' => False),
			'grant_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('client_grant_id'),
		'fk' => array(),
		'ix' => array(array('client_id','grant_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.011';
}


function openid_upgrade0_1_011()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_user_grants',array(
		'fd' => array(
			'user_grant_id' => array('type' => 'auto','nullable' => False),
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'grant_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('user_grant_id'),
		'fk' => array(),
		'ix' => array(array('account_id','grant_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.012';
}


function openid_upgrade0_1_012()
{
	$GLOBALS['egw_setup']->oProc->CreateTable('egw_openid_user_scopes',array(
		'fd' => array(
			'user_scope_id' => array('type' => 'auto','nullable' => False),
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'scope_id' => array('type' => 'int','precision' => '4','nullable' => False)
		),
		'pk' => array('user_scope_id'),
		'fk' => array(),
		'ix' => array(array('account_id','scope_id')),
		'uc' => array()
	));

	return $GLOBALS['setup_info']['openid']['currentver'] = '0.1.013';
}

