<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\Serializer as ResponseSerializer;
use Zend\Diactoros\Request\Serializer as RequestSerializer;

final class ZendDiactorosToStringMessageFormatter implements ServerRequestFormatter, ResponseFormatter
{
    public function formatResponse(ResponseInterface $response): FormattedMessage
    {
        $string = ResponseSerializer::toString($response);

        return FormattedMessage::fromString($string);
    }

    public function formatServerRequest(ServerRequestInterface $request): FormattedMessage
    {
        $string = RequestSerializer::toString($request);

        return FormattedMessage::fromString($string);
    }
}
