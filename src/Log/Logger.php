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

namespace EGroupware\OpenID\Log;

use Monolog;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\HandlerInterface;

/**
 * Extend Monolog\Logger to log by default to "$files/openid/request.log"
 */
class Logger extends Monolog\Logger
{
    /**
     * @param string             $name       The logging channel
     * @param HandlerInterface[] $handlers   Optional stack of handlers, the first one in the array is called first, etc.
     * @param callable[]         $processors Optional array of processors
     */
    public function __construct($name, array $handlers = array(), array $processors = array())
	{
		$log = $GLOBALS['egw_info']['server']['files_dir'].'/openid/request.log';

		if (!$handlers && file_exists($log))
		{
			$lineFormatter = new LineFormatter(
				null, // Format of message in log, default [%datetime%] %channel%.%level_name%: %message% %context% %extra%\n
				null, // Datetime format
				true, // allowInlineLineBreaks option, default false
				true  // ignoreEmptyContextAndExtra option, default false
			);
			$debugHandler = new StreamHandler($log, self::DEBUG);
			$debugHandler->setFormatter($lineFormatter);
			$handlers[] = $debugHandler;
		}
		parent::__construct($name, $handlers, $processors);
	}
}
