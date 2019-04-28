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

namespace EGroupware\OpenID;

use OpenIDConnectServer\Entities\ClaimSetEntity;

class ClaimExtractor extends \OpenIDConnectServer\ClaimExtractor
{
    /**
     * ClaimExtractor constructor
	 *
	 * Reimplemented to add scope and claim "roles" (array with value "user" and,
	 * if user is an EGroupware admin, also "admin").
	 *
     * @param ClaimSetEntity[] $claimSets
     */
    public function __construct($claimSets = [])
    {
		parent::__construct($claimSets);

		$this->addClaimSet(new ClaimSetEntity('roles', ['roles']));
	}

	/**
	 * For given scopes and aggregated claims get all claims that have been configured on the extractor.
	 *
	 * Reimplement to cast key picture to string (it might be an object and cast creates sharing link).
	 *
	 * @param array $scopes
	 * @param array $claims
	 * @return array
	 */
	public function extract(array $scopes, array $claims)
	{
		$data = parent::extract($scopes, $claims);

		if (isset($data['picture']))
		{
			$data['picture'] = (string)$data['picture'];
		}
		return $data;
	}
}
