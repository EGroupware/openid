<?php

namespace PhpMiddlewareTest\LogHttpMessages\Formatter;

use PhpMiddleware\LogHttpMessages\Formatter\ZendDiactorosToArrayMessageFormatter;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class ZendDiactorosToArrayMessageFormatterTest extends TestCase
{
    public function testFormatRequestToArray()
    {
        $request = new ServerRequest();
        $formatter = new ZendDiactorosToArrayMessageFormatter();

        $formattedMessage = $formatter->formatServerRequest($request);

        $this->assertInternalType('array', $formattedMessage->getValue());
    }

    public function testFormatResponeToArray()
    {
        $response = new Response();
        $formatter = new ZendDiactorosToArrayMessageFormatter();

        $formattedMessage = $formatter->formatResponse($response);

        $this->assertInternalType('array', $formattedMessage->getValue());
    }
}
