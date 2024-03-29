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

use League\OAuth2\Server\CryptKey;
use EGroupware\Api;
use Lcobucci\JWT;

// require PHP 8 fixed class before Lcobucci/JWT loads it
require_once __DIR__.'/OpenSSL.php';

/**
 * Class to create, store and retrieve our key
 *
 * Keys are automatic generated with openssl and stored in EGroupware files-dir
 * with the database password as passphrase.
 *
 * The encryption key is store in config.
 */
class Keys
{
	const APP = 'openid';
	const PRIVATE_KEY = 'private.key';
	const PUBLIC_KEY = 'public.key';
	/**
	 * Name in config for encryption-key
	 */
	const ENCRYPTION_KEY = 'encryption_key';

	/**
	 *
	 * @var array
	 */
	protected $config;

	/**
	 * Passphrase for private key, we use the database password
	 *
	 * @var string
	 */
	protected $passphrase;

	/**
	 * Constructor
	 */
	function __construct()
	{
		$this->config = Api\Config::read(self::APP);

		$this->passphrase = $GLOBALS['egw']->db->Password;

		if (empty($this->config) || empty($this->config[self::ENCRYPTION_KEY]) ||
			!file_exists(self::getAppDir().'/'.self::PRIVATE_KEY))
		{
			$this->setup();
		}
	}

	protected function getAppDir()
	{
		return realpath($GLOBALS['egw_info']['server']['files_dir']).'/'.self::APP;
	}

	/**
	 * Get the private key
	 *
	 * @return CryptKey path to file or CryptKey object
	 */
	public function getPrivateKey()
	{
		return new CryptKey('file://'.self::getAppDir().'/'.self::PRIVATE_KEY, $this->passphrase);
	}

	/**
	 * Get private key as string without passphrase
	 *
	 * @return string
	 * @throws \Exception
	 */
	public function getPrivateKeyString()
	{
		if (!($key = openssl_pkey_get_private('file://'.self::getAppDir().'/'.self::PRIVATE_KEY, $this->passphrase)) ||
			!openssl_pkey_export ($key, $out))
		{
			throw new \Exception("Cound not get private key, maybe passphrase is wrong!");
		}
		return $out;
	}

	/**
	 * Get the public key
	 *
	 * @return string path to file
	 */
	public function getPublicKey()
	{
		return 'file://'.self::getAppDir().'/'.self::PUBLIC_KEY;
	}

	/**
	 * Get kid used in JWK for our public key
	 *
	 * @return string
	 */
	public function getKid(string &$pub_key=null)
	{
		$pub_key = file_get_contents($this->getPublicKey());

		return md5($pub_key);
	}

	/**
	 * Get JSON Web Key from our public key
	 *
	 * @return array
	 */
	public function getJWK()
	{
		$kid = $this->getKID($pub_key);
		$keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($pub_key));

		return [
			'alg' => 'RS256',
			'kty' => 'RSA',
			'kid' => $kid,
			'use' => 'sig',
			'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['n'])), '='),
			'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['e'])), '='),
		];
	}

	/**
	 * Get encryption key
	 *
	 * @return string with base64 encoded random_bytes(32)
	 */
	public function getEncryptionKey()
	{
		return $this->config[self::ENCRYPTION_KEY];
	}

	/**
	 * Generate the used openssl private- / public-key-pair and our encryption key
	 *
	 * @throws \Exception if key-pair can not be generated or stored
	 */
	protected function setup()
	{
		if (empty($this->config[self::ENCRYPTION_KEY]))
		{
			$this->config[self::ENCRYPTION_KEY] = base64_encode(random_bytes(32));

			Api\Config::save_value(self::ENCRYPTION_KEY,
				$this->config[self::ENCRYPTION_KEY], self::APP, true);
		}

		if (!file_exists(($app_dir = self::getAppDir())))
		{
			mkdir($app_dir);
		}

		$private_key_path = $app_dir.'/'.self::PRIVATE_KEY;
		$public_key_path = $app_dir.'/'.self::PUBLIC_KEY;

		if (!file_exists($private_key_path) || !file_exists($public_key_path))
		{
			// Create the private and public key
			$res = openssl_pkey_new([
				"digest_alg" => "sha512",
				"private_key_bits" => 2048,
				"private_key_type" => OPENSSL_KEYTYPE_RSA,
			]);

			if ($res === false)
			{
				throw new \Exception('Error generating key-pair!');
			}

			// Extract the public key from $res to $pubKey
			$details = openssl_pkey_get_details($res);

			// Extract the private key from $res
			$public_key = null;
			openssl_pkey_export($res, $public_key, $this->passphrase);

			if (!file_put_contents($public_key_path, $details["key"]) ||
				!file_put_contents($private_key_path, $public_key.$details["key"]))
			{
				throw new \Exception('Error storing key-pair!');
			}

			// fix permisions to only allow webserver access
			chmod($public_key_path, 0600);
			chmod($private_key_path, 0600);
		}
	}

	/**
	 * Get Lcobucci JWT configuration object to generate and verify JWT using the OpenID key-pair
	 *
	 * @return JWT\Configuration
	 */
	public function jwtConfiguration() : JWT\Configuration
	{
		$privateKey = $this->getPrivateKey();
		return JWT\Configuration::forAsymmetricSigner(
			new JWT\Signer\Rsa\Sha256(),
			new JWT\Signer\Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()),
			new JWT\Signer\Key($this->getPublicKey())
		);
	}
}
