<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: admin-command to add or modify clients
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\AdminCmds;

use admin_cmd;
use EGroupware\Api;
use EGroupware\OpenID\Repositories\ClientRepository;
use EGroupware\OpenID\Repositories\GrantRepository;
use EGroupware\OpenID\Repositories\ScopeRepository;

/**
 * admin-command to add or modify clients
 *
 * Can also be used via command line:
 *
 * admin/admin-cli.php --openid-client admin[@domain],admin-password,identifier=<identifier>,[secret=<pw>,]name=<name>,grants[]=<grant>,scopes[]=<scope>
 *
 * @property string $identifier
 * @property string $secret only changed if non-empty!
 * @property string $redirect_uri
 * @property string $name
 * @property array $grants allowed grants
 * @property array $scopes =null to limit scopes, default all allowed
 * @property string $update =null to allow renaming client-identifiers
 * @property boolean $active =null false to deactive client (name can NOT be "status"!)
 * @property-read int $client_id numerical id after save
 */
class Client extends admin_cmd
{
	/**
	 * allow to call via admin/admin-cli.php --openid-client
	 */
	const SETUP_CLI_CALLABLE = true;

	/**
	 * Client repository
	 *
	 * @var ClientRepository
	 */
	protected $repo;

	/**
	 * @var GrantRepository
	 */
	protected $grant_repo;

	/**
	 * @var ScopeRepository
	 */
	protected $scope_repo;

	/**
	 * Constructor
	 *
	 * @param array $data
	 */
	function __construct(array $data)
	{
		$this->repo = new ClientRepository();
		$this->grant_repo = new GrantRepository();
		$this->scope_repo = new ScopeRepository();

		parent::__construct($data);
	}

	/**
	 * Generate human readable name of object
	 *
	 * @return string
	 */
	public static function name()
	{
		return lang('OpenID / OAuth2 Server').' '.lang('Client');
	}

	/**
	 * String representation of command
	 *
	 * @return string
	 */
	public function __tostring()
	{
		return self::name().(!empty($this->name) ? ': '.$this->name : '');
	}

	/**
	 * Executes the command
	 *
	 * @param boolean $check_only =false only run the checks (and throw the exceptions), but not the command itself
	 * @return string success message
	 * @throws Exception()
	 */
	protected function exec($check_only=false)
	{
		// validate data
		$this->old = $this->repo->read(!empty($this->update) ? $this->update : $this->identifier);

		if (!$this->old && !empty($this->update=null))
		{
			throw new WrongUserinput("Client '$this->update' NOT found!");
		}

		if (!$this->old)
		{
			foreach(['identifier', 'secret', 'grants', 'redirect_uri'] as $required)
			{
				if (empty($this->data[$required]))
				{
					throw new WrongUserinput("Missing required parameter $required!");
				}
			}
			if (empty($this->name)) $this->name = $this->identifier;
			unset($this->old);
		}
		if (isset($this->grants))
		{
			$this->grants = array_keys($this->grant_repo->checkGrants($this->grants));
		}
		if (isset($this->scopes))
		{
			$this->scopes = array_keys($this->scope_repo->checkScopes($this->scopes));
		}
		if ($check_only) return null;

		if (!isset($this->old))
		{
			$this->repo->init([
				'client_name' => $this->name,
				'client_identifier' => $this->identifier,
				'client_secret' => $this->secret,
				'client_redirect_uri' => $this->redirect_uri,
				'client_status' => isset($this->active) ? (bool)$this->active : true,
				'client_updated' => $this->repo->now,
				'client_created' => $this->repo->now,
				'client_creator' => $GLOBALS['egw_info']['user']['account_id'],
				'client_modifier' => $GLOBALS['egw_info']['user']['account_id'],
			]);
			if ($this->repo->save())
			{
				throw new WrongParameter(lang("Error saving client!"));
			}
		}
		else
		{
			$this->old = Api\Db::strip_array_keys($this->old, 'client_')+['active' => $this->old['client_status']];
			$to_update = [];
			foreach($this->data as $name => $value)
			{
				if (isset($this->$name) && $this->$name != $this->old[$name] &&
					!in_array($name, ['old', 'update', 'secret']))
				{
					$to_update['client_'.$name] = $value;
				}
			}
			// update password only if it's given
			if (!empty($this->secret))
			{
				$to_update['client_secret'] = $this->secret;
			}
			// only store changed fields
			$this->old = array_intersect_key($this->old, Api\Db::strip_array_keys($to_update, 'client_'));

			$to_update['client_updated'] = $this->repo->now;
			$to_update['client_modifier'] = $GLOBALS['egw_info']['user']['account_id'];
			if (isset($to_update['client_status']))
			{
				$to_update['client_status'] = $to_update['client_active'];
			}
			if ($this->repo->update($to_update))
			{
				throw new WrongParameter(lang("Error saving client!"));
			}
		}
		$this->client_id = $this->repo->data['client_id'];

		// saving allowd grants and scopes in their tables
		if (isset($this->grants)) $this->repo->saveGrants($this->client_id, $this->grants);
		if (isset($this->scopes)) $this->repo->saveScopes($this->client_id, $this->scopes);

		return isset($this->active) && !$this->active ? lang('Client disabled.') : lang('Client saved.');
	}

	/**
	 * Return (human readable) labels for keys of changes
	 *
	 * Reading them from admin.account template
	 *
	 * @return array
	 */
	function get_change_labels()
	{
		$labels = parent::get_change_labels();

		$labels += [
			'name'   => lang('Name'),
			'identifier' => lang('Identifier'),
			'secret' => lang('Secret'),
			'redirect_uri' => lang('Redirect URI'),
			'grants' => lang('Allowed grants'),
			'scopes' => lang('Limit scopes'),
			'active' => lang('Status'),
		];

		return $labels;
	}

	/**
	 * Return widget types (indexed by field key) for changes
	 *
	 * Used by historylog widget to show the changes the command recorded.
	 */
	function get_change_widgets()
	{
		$widgets = parent::get_change_widgets();

		$widgets['grants'] = $this->grant_repo->selOptions();
		$widgets['scopes'] = $this->scope_repo->selOptions();
		$widgets['active'] = [lang('Disabled'), lang('Active')];

		return $widgets;
	}
}