<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

use Psr\Http\Message\ServerRequestInterface;

interface ServerRequestFormatter
{
    public function formatServerRequest(ServerRequestInterface $request) : FormattedMessage;
}
