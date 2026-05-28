<?php

namespace PhpMiddlewareTest\LogHttpMessages\Formatter;

use PhpMiddleware\LogHttpMessages\Formatter\FormattedMessage;
use PHPUnit\Framework\TestCase;

class FormattedMessageTest extends TestCase
{
    public function testCanCreateFromString()
    {
        $formattedMessage = FormattedMessage::fromString('foo');

        $this->assertSame('foo', $formattedMessage->getValue());
    }

    public function testCanCreateFromArray()
    {
        $formattedMessage = FormattedMessage::fromArray(['boo' => 'baz']);

        $this->assertSame(['boo' => 'baz'], $formattedMessage->getValue());
    }

    public function testCanCreateEmpty()
    {
        $formattedMessage = FormattedMessage::createEmpty();

        $this->assertNull($formattedMessage->getValue());
    }
}
