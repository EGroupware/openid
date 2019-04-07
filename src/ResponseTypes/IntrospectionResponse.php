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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;

class IntrospectionResponse extends AbstractResponseType
{
    /**
     * @var bool
     */
    protected $valid = false;

    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * Set the validity of the response.
     *
     * @param bool $bool
     */
    public function setValidity($bool)
    {
        $this->valid = (bool)$bool;
    }

    /**
     * Set the request.
     *
     * @param ServerRequestInterface $request
     */
    public function setRequest(ServerRequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * Return the valid introspection parameters.
     *
     * @return array
     */
    protected function validIntrospectionResponse()
    {
        $responseParams = [
            'active' => true,
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Return the invalid introspection parameters.
     *
     * @return array
     */
    protected function invalidIntrospectionResponse()
    {
        return [
            'active' => false,
        ];
    }

    /**
     * Extract the introspection response.
     *
     * @return array
     */
    public function getIntrospectionResponseParams()
    {
        return $this->isValid() ?
            $this->validIntrospectionResponse() :
            $this->invalidIntrospectionResponse();
    }

    /**
     * Check if the response is valid.
     *
     * @return bool
     */
    protected function isValid()
    {
        return $this->valid === true;
    }

    /**
     * Generate a HTTP response.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $responseParams = $this->getIntrospectionResponseParams();

        $response = $response
                ->withStatus(200)
                ->withHeader('pragma', 'no-cache')
                ->withHeader('cache-control', 'no-store')
                ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));

        return $response;
    }

    /**
     * Add custom fields to your Introspection response here, then set your introspection
     * reponse in AuthorizationServer::setIntrospectionResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array
     */
    protected function getExtraParams()
    {
        return [];
    }
}
