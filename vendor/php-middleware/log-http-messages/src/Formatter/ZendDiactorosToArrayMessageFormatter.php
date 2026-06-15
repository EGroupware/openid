<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\ArraySerializer as ResponseSerializer;
use Zend\Diactoros\Request\ArraySerializer as RequestSerializer;

final class ZendDiactorosToArrayMessageFormatter implements ServerRequestFormatter, ResponseFormatter
{
    public function formatResponse(ResponseInterface $response): FormattedMessage
    {
        $array = ResponseSerializer::toArray($response);

        return FormattedMessage::fromArray($array);
    }

    public function formatServerRequest(ServerRequestInterface $request): FormattedMessage
    {
        $array = RequestSerializer::toArray($request);

        return FormattedMessage::fromArray($array);
    }

}
