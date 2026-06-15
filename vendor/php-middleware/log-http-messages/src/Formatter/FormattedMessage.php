<?php

declare (strict_types=1);

namespace PhpMiddleware\LogHttpMessages\Formatter;

final class FormattedMessage
{
    private $value;

    public static function fromString(string $value) : self
    {
        $instance = new self();
        $instance->value = $value;

        return $instance;
    }

    public static function fromArray(array $value) : self
    {
        $instance = new self();
        $instance->value = $value;

        return $instance;
    }

    public static function createEmpty() : self
    {
        return new self();
    }

    /**
     * @return array|string|null
     */
    public function getValue()
    {
        return $this->value;
    }
}
