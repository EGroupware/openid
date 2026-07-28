<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Adapts a Slim2/3-style "double-pass" middleware (invokable as
 * ($request, $response, $next)) to PSR-15, for upstream packages that still use that calling
 * convention - eg. league/oauth2-server's Middleware\ResourceServerMiddleware, which Slim 4 (only
 * supporting PSR-15 middleware natively) can no longer call directly.
 */
class LegacyMiddlewareAdapter implements MiddlewareInterface
{
	/**
	 * @var callable
	 */
	protected $middleware;

	/**
	 * @var ResponseFactoryInterface
	 */
	protected $responseFactory;

	function __construct(callable $middleware, ResponseFactoryInterface $responseFactory)
	{
		$this->middleware = $middleware;
		$this->responseFactory = $responseFactory;
	}

	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface
	{
		$next = static function(ServerRequestInterface $request, ResponseInterface $response) use ($handler)
		{
			unset($response);	// unused: $handler creates its own response
			return $handler->handle($request);
		};
		return ($this->middleware)($request, $this->responseFactory->createResponse(), $next);
	}
}
