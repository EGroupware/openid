<?php
/**
 * EGroupware OpenID Connect / OAuth2 server logging
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/php-middleware/log-http-messages
 */

declare (strict_types=1);

namespace EGroupware\OpenID\Log;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use PhpMiddleware\LogHttpMessages\Formatter\ResponseFormatter;
use PhpMiddleware\LogHttpMessages\Formatter\ServerRequestFormatter;
use PhpMiddleware\LogHttpMessages\Formatter\FormattedMessage;

/**
 * Format request and response as they have been originaly send or will be send
 *
 * Does log all tokens and usernames, but no cleartext-passwords (replaced with "...")
 */
class HttpFormatter implements ServerRequestFormatter, ResponseFormatter
{
	public function formatResponse(ResponseInterface $response): FormattedMessage
	{
		return FormattedMessage::fromString(
			'HTTP/'.$response->getProtocolVersion().' '.
				$response->getStatusCode().' '.$response->getReasonPhrase()."\r\n".
			self::formatHeaders($response->getHeaders())."\r\n".
			self::formatBody($response->getBody())
		);
	}

	public function formatServerRequest(ServerRequestInterface $request): FormattedMessage
	{
		return FormattedMessage::fromString(
			$request->getMethod().' '.$request->getRequestTarget().
				' HTTP/'.$request->getProtocolVersion()."\r\n".
			self::formatHeaders($request->getHeaders())."\r\n".
			self::formatBody($request->getBody())
		);
	}

	protected static function formatBody($body)
	{
		// do NOT log cleartext passwords / client_secret
		return preg_replace('/&(client_secret|password)=[^&]*(&|$)/', '&$1=...$2', (string)$body).
			"\n";	// not part of HTTP response, but for better readability in logs
	}

	protected static function formatHeaders(array $headers)
	{
		$str = '';
		foreach($headers as $name => $values)
		{
			switch(strtoupper($name))
			{
				case 'PHP_AUTH_USER':
				case 'PHP_AUTH_PW':
					continue 2;
				case 'HTTP_AUTHORIZATION':
					// do NOT log cleartext passwords
					if (strpos($values[0], 'Basic ') === 0)
					{
						list($type, $value) = explode(' ', $values[0]);
						list($user) = explode(':', base64_decode($value));
						$values = [$type.' '.trim(base64_encode($user.':'), '=').
							"... = base64('$user:...')"];
					}
					break;
			}
			foreach($values as $value)
			{
				// write headers like they look by default
				if (stripos($name, 'HTTP_') === 0) $name = substr($name, 5);
				$str .= implode('-', array_map('ucfirst', preg_split('/[_-]/', strtolower($name))));

				$str .= ': '.$value."\r\n";
			}
		}
		return $str;
	}
}
