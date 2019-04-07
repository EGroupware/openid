<?php

namespace EGroupware\OpenID;

use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenID\IntrospectionValidators\BearerTokenValidator;
use EGroupware\OpenID\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use EGroupware\OpenID\ResponseTypes\IntrospectionResponse;
use Psr\Http\Message\ServerRequestInterface;

use League\OAuth2\Server\CryptKey;

class Introspector
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var CryptKey
     */
    private $privateKey;

    /**
     * @var null|IntrospectionValidatorInterface
     */
    private $introspectionValidator;

    /**
     * New Introspector instance.
     *
     * @param AccessTokenRepositoryInterface  $accessTokenRepository
     * @param CryptKey                        $privateKey
     * @param IntrospectionValidatorInterface $introspectionValidator
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKey $privateKey,
        IntrospectionValidatorInterface $introspectionValidator = null
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->privateKey = $privateKey;
        $this->introspectionValidator = $introspectionValidator;
    }

    /**
     * Validate the introspection request.
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     */
    public function validateIntrospectionRequest(ServerRequestInterface $request)
    {
        if ($request->getMethod() !== 'POST') {
            throw OAuthServerException::accessDenied('Invalid request method');
        }
    }

    /**
     * Return an introspection response.
     *
     * @param ServerRequestInterface $request
     * @param IntrospectionResponse  $responseType
     *
     * @return IntrospectionResponse
     */
    public function respondToIntrospectionRequest(
        ServerRequestInterface $request,
        IntrospectionResponse $responseType
    ) {
        $validator = $this->getIntrospectionValidator();

        if ($validator->validateIntrospection($request)) {
            $responseType->setRequest($request);
            $responseType->setValidity(true);
        }

        return $responseType;
    }

    /**
     * Get the introspection validator, falling back to the bearer token validator if not set.
     *
     * @return IntrospectionValidatorInterface
     */
    protected function getIntrospectionValidator()
    {
        if ($this->introspectionValidator instanceof IntrospectionValidatorInterface === false) {
            $this->introspectionValidator = new BearerTokenValidator($this->accessTokenRepository);
            $this->introspectionValidator->setPrivateKey($this->privateKey);
        }

        return $this->introspectionValidator;
    }
}
