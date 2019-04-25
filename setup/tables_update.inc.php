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

function openid_upgrade19_1()
{
	$GLOBALS['egw_setup']->db->insert('egw_openid_scopes', [
		'scope_identifier' => 'roles',
		'scope_description' => 'Administration rights or regular user',
		'scope_created'    => time(),
	], false, __LINE__, __FILE__, 'openid');

	return $GLOBALS['setup_info']['openid']['currentver'] = '19.1.001';
}
