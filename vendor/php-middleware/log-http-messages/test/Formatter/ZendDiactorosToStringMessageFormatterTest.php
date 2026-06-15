<?php

namespace PhpMiddlewareTest\LogHttpMessages\Formatter;

use PhpMiddleware\LogHttpMessages\Formatter\ZendDiactorosToStringMessageFormatter;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class ZendDiactorosToStringMessageFormatterTest extends TestCase
{
    public function testFormatRequestToArray()
    {
        $request = new ServerRequest();
        $formatter = new ZendDiactorosToStringMessageFormatter();

        $formattedMessage = $formatter->formatServerRequest($request);

        $this->assertInternalType('string', $formattedMessage->getValue());
    }

    public function testFormatResponeToArray()
    {
        $response = new Response();
        $formatter = new ZendDiactorosToStringMessageFormatter();

        $formattedMessage = $formatter->formatResponse($response);

        $this->assertInternalType('string', $formattedMessage->getValue());
    }
}
