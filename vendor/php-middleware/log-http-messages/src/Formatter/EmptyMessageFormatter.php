<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @codeCoverageIgnore
 */
final class EmptyMessageFormatter implements ServerRequestFormatter, ResponseFormatter
{
    public function formatServerRequest(ServerRequestInterface $request): FormattedMessage
    {
        return FormattedMessage::createEmpty();
    }

    public function formatResponse(ResponseInterface $response): FormattedMessage
    {
        return FormattedMessage::createEmpty();
    }
}
