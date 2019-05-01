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
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 */

namespace EGroupware\OpenID\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use EGroupware\Api;

/**
 * User entity
 */
class UserEntity extends Base implements UserEntityInterface, ClaimSetInterface
{
	/**
	 * Domain used to construct user-identifiers
	 *
	 * @var string
	 */
	protected $account_domain;

	/**
	 * Construct by username or nummerical identifier
	 *
	 * @param string|int $account user-identifier, username or nummerical account_id
	 * @throws Api\Exception\WrongParameter
	 */
	public function __construct($account)
	{
		$accounts = Api\Accounts::getInstance();

		$this->account_domain = !empty($GLOBALS['egw_info']['user']['domain']) ?
			$GLOBALS['egw_info']['user']['domain'] :
			$GLOBALS['egw_info']['server']['default_domain'];

		if (empty($account))
		{
			return;	// otherwise client credentials claims allways fail
		}
		if ((is_int($account) || is_numeric($account)))
		{
			if ($accounts->exists($account) !== 1)
			{
				throw new Api\Exception\WrongParameter("Invalid identifier #$account!");
			}
			$this->id = (int)$account;
		}
		else
		{
			if (strpos($account, '@') !== false &&
				substr($account, -strlen($this->account_domain)-1) === '@'.$this->account_domain)
			{
				$account = substr($account, 0, -strlen($this->account_domain)-1);
			}
			if (!($this->id = $accounts->name2id($account)))
			{
				throw new Api\Exception\WrongParameter("Invalid username '$account'!");
			}
		}
	}
	/**
	 * Return the user's identifier.
	 *
	 * @return mixed
	 */
	public function getIdentifier()
	{
		return empty($this->id) ? null :
			Api\Accounts::id2name($this->id);//.'@'.$this->account_domain;
	}

	/**
	 * Get claims / user profile data
	 *
	 * @return array
	 */
	public function getClaims()
	{
		$contacts = new Api\Contacts();

		if (empty($this->id))
		{
			return [];
		}
		if (!($contact = $contacts->read('account:'.$this->id, true)))	// no ACL check, as we might have no session
		{
			throw new Api\Exception\WrongParameter("No contact-data for account #$this->id found!");
		}

		// create a session-independent url / sharing link of the photo
		$photo = new Api\Contacts\Photo($contact);
		// we run as anonymous user, which might have not rights for addressbook
		$GLOBALS['egw_info']['user']['apps']['addressbook'] = true;
		// create sharing-link of picture for the current user (no session!)
		Api\Vfs::$user = $this->getID();

		if (!$photo->hasPhoto())
		{
			$photo = empty($contact['email']) ? null :
				// can't hurt to try Gravatar, if we have no picture but an email address
				'https://www.gravatar.com/avatar/'.md5(strtolower(trim($contact['email'])));
		}

		// change our 2 or 5 letter (es-es, pt-br, zh-tw --> lang-country) lang code and country into a locale
		$preferences = new Api\Preferences($this->getID());
		$prefs = $preferences->read_repository();
		if (strlen($prefs['common']['lang']) === 5)
		{
			list($lang, $country) = explode('-', $prefs['common']['lang']);
		}
		else
		{
			$lang = $prefs['common']['lang'];
			$country = $prefs['common']['country'];
		}
		$locale = strtolower($lang).'_'.strtoupper($country);

		return [
			'id' => $this->getIdentifier(),
			// profile
			'name' => $contact['n_fn'],
			'family_name' => $contact['n_family'],
			'given_name' => $contact['n_given'],
			'middle_name' => $contact['n_middle'],
			'nickname' => '',
			'preferred_username' => Api\Accounts::id2name($this->id),
			'profile' => '',
			'picture' => $photo,
			'website' => $contact['url'],
			'gender' => 'n/a',
			'birthdate' => $contact['bday'],	// format?
			'zoneinfo' => Api\DateTime::$user_timezone->getName(),
			'locale' => $locale,
			'updated_at' => Api\DateTime::to($contact['modified'], 'Y-m-d'),
			// email
			'email' => $contact['email'],
			'email_verified' => true,
			// phone
			'phone_number' => !empty($contact['tel_prefer']) && !empty($contact[$contact['tel_prefer']]) ?
				$contact[$contact['tel_prefer']] : $contact['tel_cell'],
			'phone_number_verified' => false,
			// address
			'address' => [
				'formatted' => $contact['label'],
				'street_address' => $contact['adr_one_street'],
				'locality' => $contact['adr_one_locality'],
				'postal_code' => $contact['adr_one_postalcode'],
				'country' => $contact['adr_one_countryname'],
				'region' => $contact['adr_one_region'],
			],
			// user roles: "user", "admin"
			'roles' => array_merge(['user'], array_intersect(array_keys($GLOBALS['egw']->acl->get_user_applications($this->id)), ['admin'])),
		];
	}
}
