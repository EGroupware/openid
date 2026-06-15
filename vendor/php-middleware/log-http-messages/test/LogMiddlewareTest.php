<?php

namespace PhpMiddlewareTest\LogHttpMessages;

use PhpMiddleware\LogHttpMessages\Formatter\EmptyMessageFormatter;
use PhpMiddleware\LogHttpMessages\LogMiddleware;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

class LogMiddlewareTest extends TestCase
{
    /** @var LogMiddleware */
    private $middleware;
    /** @var LoggerInterface|MockObject */
    private $logger;
    private $handler;

    protected function setUp()
    {
        $response = $this->createMock(ResponseInterface::class);

        $this->handler = $this->createMock(RequestHandlerInterface::class);
        $this->handler->method('handle')->willReturn($response);

        $formatter = new EmptyMessageFormatter();
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->middleware = new LogMiddleware($formatter, $formatter, $this->logger, LogLevel::ALERT);
    }

    public function testLogFormattedMessages()
    {
        /** @var ServerRequestInterface|MockObject $request */
        $request = $this->createMock(ServerRequestInterface::class);

        $this->logger->expects($this->once())->method('log')
            ->with(LogLevel::ALERT, LogMiddleware::LOG_MESSAGE, ['request' => null, 'response' => null]);

        $this->middleware->process($request, $this->handler);
    }
}
