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

/**
 * Class to create, store and retrieve our key
 *
 * Currently keys are generated with openssl and stored in EGroupware files-dir:
 *
 * cd /path/to/egroupware/files
 * mkdir openid
 * openssl genrsa -out openid/private.key 2048
 * openssl rsa -in openid/private.key -pubout > openid/public.key
 * chgrp -R www-run openid
 *
 * Later installation should create the key-pair and store it securely in config.
 *
 * Following can be used for a private key with passphrase:
 *
 * new CryptKey('file://path/to/private.key', 'passphrase');
 */
class Key
{
	/**
	 * Get the private key
	 *
	 * @return string|CryptKey path to file or CryptKey object
	 */
	function getPrivate()
	{
		return 'file://'.realpath($GLOBALS['egw_info']['server']['files_dir']).
			'/openid/private.key';
	}

	/**
	 * Get the public key
	 *
	 * @return string path to file
	 */
	function getPublic()
	{
		return 'file://'.realpath($GLOBALS['egw_info']['server']['files_dir']).
			'/openid/public.key';
	}
}
