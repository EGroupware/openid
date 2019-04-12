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
 */
class HttpFormatter implements ServerRequestFormatter, ResponseFormatter
{
	public function formatResponse(ResponseInterface $response): FormattedMessage
	{
		return FormattedMessage::fromString(
			'HTTP/'.$response->getProtocolVersion().' '.
				$response->getStatusCode().' '.$response->getReasonPhrase()."\r\n".
			self::formatHeaders($response->getHeaders())."\r\n".
			// do NOT log cleartext passwords / client_secret
			preg_replace('/&client_secret=secret(&|$)/', '********', $response->getBody()).
			"\n"	// not part of HTTP response, but for better readability in logs
		);
	}

	public function formatServerRequest(ServerRequestInterface $request): FormattedMessage
	{
		return FormattedMessage::fromString(
			$request->getMethod().' '.$request->getRequestTarget().
				' HTTP/'.$request->getProtocolVersion()."\r\n".
			self::formatHeaders($request->getHeaders())."\r\n".
			$request->getBody()
		);
	}

	protected static function formatHeaders(array $headers)
	{
		$str = '';
		foreach($headers as $name => $values)
		{
			foreach($values as $value)
			{
				// write heads like they look by default
				if (stripos($name, 'HTTP_') === 0) $name = substr($name, 5);
				$str .= implode('-', array_map('ucfirst', explode('-', strtolower($name))));

				// do NOT log cleartext passwords
				if ($name === 'Authorization' && strpos($value, 'Basic ') === 0)
				{
					list($type, $val) = explode(' ', $value);
					list($user) = explode(':', base64_decode($val));
					$value = $type.' '.trim(base64_encode($user.':'), '=').
						"... = base64('$user:...')";
				}
				$str .= ': '.$value."\r\n";
			}
		}
		return $str;
	}
}
