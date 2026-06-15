# log-http-messages middleware [![Build Status](https://travis-ci.org/php-middleware/log-http-messages.svg)](https://travis-ci.org/php-middleware/log-http-messages)
PSR-15 middleware for log PSR-7 HTTP messages using PSR-3 logger

This middleware provide framework-agnostic possibility to log request and response messages to PSR-3 logger.

## Installation

```
composer require php-middleware/log-http-messages
```

To log http messages you need pass into `LogRequestMiddleware` implementation of
`PhpMiddleware\LogHttpMessages\Formatter\ServerRequestFormatter`,
`PhpMiddleware\LogHttpMessages\Formatter\ResponseFormatter`,
instance `Psr\Log\LoggerInterface` and add this middleware to your middleware runner.
You can also set log level (`Psr\Log\LogLevel::INFO` as default) and log message (`Request/Response` as default).

Provided implementation of formatters:

* `PhpMiddleware\LogHttpMessages\Formatter\EmptyMessageFormatter`,
* `PhpMiddleware\LogHttpMessages\Formatter\ZendDiactorosToArrayMessageFormatter`,
* `PhpMiddleware\LogHttpMessages\Formatter\ZendDiactorosToStringMessageFormatter`.

```php
$formatter = PhpMiddleware\LogHttpMessages\Formatter\ZendDiactorosToArrayMessageFormatter();
$logMiddleware = new PhpMiddleware\LogHttpMessages\LogMiddleware($formatter, $formatter, $logger);

$app = new MiddlewareRunner();
$app->add($logMiddleware);
$app->run($request, $response);
```

## It's just works with any modern php framework and logger!

Middleware tested on:
* [Expressive](https://github.com/zendframework/zend-expressive)
* [monolog](https://github.com/Seldaek/monolog)

Middleware should works with:
* [Slim 3.x](https://github.com/slimphp/Slim)
* [zend-log 2.6](https://github.com/zendframework/zend-log)

And any other modern framework [supported PSR-15 middlewares and PSR-7](https://mwop.net/blog/2015-01-08-on-http-middleware-and-psr-7.html) and [PSR-3 implementation](http://www.php-fig.org/psr/psr-3/) logger.
