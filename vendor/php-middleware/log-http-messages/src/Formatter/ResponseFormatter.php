<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

use Psr\Http\Message\ResponseInterface;

interface ResponseFormatter
{
    public function formatResponse(ResponseInterface $response) : FormattedMessage;
}