<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * Implement RFC7662 OAuth 2.0 Token Introspection
 * Until OAuth2 server pull request #925 is not merged:
 * @link https://github.com/thephpleague/oauth2-server/pull/925
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @link https://github.com/thephpleague/oauth2-server
 */

namespace EGroupware\OpenID\ResponseTypes;

use Lcobucci\JWT\UnencryptedToken;
use EGroupware\OpenID\Keys;

class BearerTokenIntrospectionResponse extends IntrospectionResponse
{
    /**
     * Add the token data to the response.
     *
     * @return array
     */
    protected function validIntrospectionResponse()
    {
        $token = $this->getTokenFromRequest();
        $claims = $token->claims();

        $exp = $claims->get('exp');
        $iat = $claims->get('iat');
        // lcobucci/jwt 5.x's permittedFor() always stores "aud" as an array (RFC7519 allows
        // multiple audiences); we only ever issue tokens for a single client, so keep the RFC7662
        // "client_id" field a plain string like it always was.
        $aud = $claims->get('aud');

        $responseParams = [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $claims->get('scopes', []),
            'client_id' => is_array($aud) ? reset($aud) : $aud,
            'exp' => $exp instanceof \DateTimeInterface ? $exp->getTimestamp() : $exp,
            'iat' => $iat instanceof \DateTimeInterface ? $iat->getTimestamp() : $iat,
            'sub' => $claims->get('sub'),
            'jti' => $claims->get('jti'),
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Gets the token from the request body.
     *
     * @return UnencryptedToken
     */
    protected function getTokenFromRequest()
    {
        $jwt = $this->request->getParsedBody()['token'] ?? null;

        return (new Keys())->jwtConfiguration()->parser()->parse($jwt);
    }
}
