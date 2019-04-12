<?php
/**
 * EGroupware OpenID Connect / OAuth2 server logging
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/php-middleware/log-http-messages
 */

declare (strict_types=1);

namespace EGroupware\OpenID\Log;

use PhpMiddleware\LogHttpMessages\Formatter\ResponseFormatter;
use PhpMiddleware\LogHttpMessages\Formatter\ServerRequestFormatter;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\LogLevel;

/**
 * Participant in processing a server request and response.
 *
 * An HTTP middleware component participates in processing an HTTP message:
 * by acting on the request, generating the response, or forwarding the
 * request to a subsequent middleware and possibly acting on its response.
 */
class Middleware implements MiddlewareInterface
{
	private $logger;
	private $level;
	private $requestFormatter;
	private $responseFormatter;

	public function __construct(
		ServerRequestFormatter $requestFormatter,
		ResponseFormatter $responseFormatter,
		Logger $logger=null,
		string $level = LogLevel::DEBUG
	) {
		$this->requestFormatter = $requestFormatter;
		$this->responseFormatter = $responseFormatter;
		$this->logger = $logger;
		$this->level = $level;
	}

    /**
     * Process an incoming server request.
     *
     * Processes an incoming server request in order to produce a response.
     * If unable to produce the response itself, it may delegate to the provided
     * request handler to do so.
     */
	public function process(ServerRequest $request, RequestHandlerInterface $handler): Response
	{
		$formattedRequest = $this->requestFormatter->formatServerRequest($request);
		$this->logger->log($this->level, $formattedRequest->getValue());

		$response = $handler->handle($request);

		$formattedResponse = $this->responseFormatter->formatResponse($response);
		$this->logger->log($this->level, $formattedResponse->getValue());

		return $response;
	}
}
