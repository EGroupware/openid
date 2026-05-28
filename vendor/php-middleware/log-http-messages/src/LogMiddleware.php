<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages;

use PhpMiddleware\LogHttpMessages\Formatter\ResponseFormatter;
use PhpMiddleware\LogHttpMessages\Formatter\ServerRequestFormatter;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\LogLevel;

final class LogMiddleware implements MiddlewareInterface
{
    const LOG_MESSAGE = 'Request/Response';

    private $logger;
    private $level;
    private $requestFormatter;
    private $responseFormatter;
    private $logMessage;

    public function __construct(
        ServerRequestFormatter $requestFormatter,
        ResponseFormatter $responseFormatter,
        Logger $logger,
        string $level = LogLevel::INFO,
        string $logMessage = self::LOG_MESSAGE
    ) {
        $this->requestFormatter = $requestFormatter;
        $this->responseFormatter = $responseFormatter;
        $this->logger = $logger;
        $this->level = $level;
        $this->logMessage = $logMessage;
    }

    /** @inheritdoc */
    public function process(ServerRequest $request, RequestHandlerInterface $handler): Response
    {
        $response = $handler->handle($request);

        $formattedRequest = $this->requestFormatter->formatServerRequest($request);
        $formattedResponse = $this->responseFormatter->formatResponse($response);

        $this->logger->log($this->level, $this->logMessage, [
            'request' => $formattedRequest->getValue(),
            'response' => $formattedResponse->getValue(),
        ]);

        return $response;
    }
}
