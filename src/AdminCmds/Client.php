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
 * @property string $app_name =null application name, if managed as EGroupware app
 * @property string $app_index =null index page, --------- " -----------
 * @property string $app_icon =null icon url, --------- " -----------
 * @property string $app_order =2 application order, --------- " -----------
 * @property array $run_rights =null array of account_id with run-rights, ---- " ----
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
	public function __toString()
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
			$required_data = ['identifier', 'secret', 'grants', 'redirect_uri'];
			// if managed as app, both name and index are required
			if (!empty($this->data['app_name']) || !empty($this->data['app_index']))
			{
				$required_data[] = 'app_name';
				$required_data[] = 'app_index';
			}
			foreach($required_data as $required)
			{
				if (empty($this->data[$required]))
				{
					throw new WrongUserinput("Missing required parameter $required!");
				}
			}
			if (empty($this->name)) $this->name = $this->identifier;
			unset($this->old);

			if (isset($GLOBALS['egw_info']['apps'][$this->app_name]))
			{
				throw new Api\Exception\WrongUserinput(lang('This name is already been taken by an installed EGroupware application!'));
			}
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
				'app_name' => $this->app_name,
			]);
			if ($this->repo->save())
			{
				throw new WrongParameter(lang("Error saving client!"));
			}
		}
		else
		{
			$this->old = Api\Db::strip_array_keys($this->old, 'client_');
			$to_update = [];
			foreach($this->data as $name => $value)
			{
				$db_name = $name == 'active' ? 'status' : $name;
				if (isset($this->$name) && $this->$name != $this->old[$db_name] &&
					!in_array($name, ['old', 'update', 'secret', 'app_index', 'app_icon', 'app_order', 'run_rights']))
				{
					$to_update[$name === 'app_name' ? $name : 'client_'.$db_name] = $value;
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
			if ($this->repo->update($to_update))
			{
				throw new WrongParameter(lang("Error saving client!"));
			}
		}
		if (!empty($this->app_name) && (!isset($this->active) || $this->active))
		{
			$extra_msg = $this->save_application();
		}
		$this->client_id = $this->repo->data['client_id'];

		// saving allowed grants and scopes in their tables
		if (isset($this->grants)) $this->repo->saveGrants($this->client_id, $this->grants);
		if (isset($this->scopes)) $this->repo->saveScopes($this->client_id, $this->scopes);

		return isset($this->active) && !$this->active ? lang('Client disabled.') :
			lang('Client saved.').(!empty($extra_msg) ? "\n".$extra_msg : '');
	}

	/**
	 * Save data to egw_application table, if client is managed as EGroupware application
	 *
	 * @return ?string extra message, if additional OpenId run rights were necessary and therefore set
	 */
	protected function save_application()
	{
		$setup = new \setup();
		$setup->db = $GLOBALS['egw']->db;	// setup does not set it automatic and loaddb only works for setup

		$setup_info = [
			$this->app_name => [
				'name'  => $this->app_name,
				'index' => $this->app_index,
				'icon'  => $this->app_icon,
				'app_order' => $this->app_order,
				'enable' => 1,	// regular app shown in navbar
				'version' => '0.1',	// a version is required!
			],
		];

		if ($setup->app_registered($this->app_name))
		{
			$setup->update_app($this->app_name, $setup_info);
		}
		else
		{
			$setup->register_app($this->app_name, 1, $setup_info);
		}

		$acl = new Api\Acl();
		$existing = $acl->get_ids_for_location('run', 1, $this->app_name) ?: [];
		foreach(array_diff($this->run_rights, $existing) as $account_id)
		{
			$acl->add_repository($this->app_name, 'run', $account_id, 1);
		}
		foreach(array_diff($existing, $this->run_rights) as $account_id)
		{
			$acl->delete_repository($this->app_name, 'run', $account_id);
		}
		// if we need a CSP to allow framing, make sure users also have OpenID run rights, as the hook is otherwise NOT called!
		if ($this->app_index[0] !== '/' && !str_starts_with($this->app_index, Api\Framework::getUrl('/')))
		{
			$existing_openid = $acl->get_ids_for_location('run', 1, 'openid') ?: [];
			if (($needed_openid_run_rights=array_diff($this->run_rights, $existing_openid)))
			{
				foreach($needed_openid_run_rights as $account_id)
				{
					$acl->add_repository('openid', 'run', $account_id, 1);
				}
				$extra_msg = lang('Following accounts have been given %1 run rights required to set Content-Security-Policy', lang('openid')).': '.
					implode(', ', array_map(Api\Accounts::class.'::id2name', $needed_openid_run_rights));
			}
		}
		$GLOBALS['egw']->invalidate_session_cache();

		return $extra_msg ?? null;
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