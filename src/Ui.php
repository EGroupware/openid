<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID;

require_once __DIR__.'/../vendor/autoload.php';

use EGroupware\Api;

/**
 * Generate tokens (programaitic) for current user
 */
class Ui
{
	const APP = 'openid';

	/**
	 * Functions callabed via menuaction
	 *
	 * @var array
	 */
	public $public_functions = [
		'clients' => true,
		'client'  => true,
	];

	/**
	 * Current active user
	 *
	 * @var int
	 */
	protected $user;

	/**
	 * ClinetRepository
	 *
	 * @var Repository\ClientRepository
	 */
	protected $clientRepo;

	function __construct()
	{
		if (empty($GLOBALS['egw_info']['user']['apps']['admin']))
		{
			throw new NoPermission('Admin rights required!');
		}
		$this->user = $GLOBALS['egw_info']['user']['account_id'];

		$this->clientRepo = new Repositories\ClientRepository();
	}

	/**
	 * Edit/add a client
	 *
	 * @param array $content =null
	 */
	public function client(array $content=null)
	{
		if (!is_array($content))
		{
			if (!empty($_GET['client_id']))
			{
				if (!($content = $this->clientRepo->read($_GET['client_id'])))
				{
					Api\Framework::window_close(lang('Client not found!'));
				}
			}
			elseif(!empty($_GET['copy']))
			{
				if (!($content = $this->clientRepo->read($_GET['copy'])))
				{
					Api\Framework::window_close(lang('Client not found!'));
				}
				unset($content['client_id'], $content['client_created'], $content['client_updated']);
				$content['msg'] = lang('Client copied. Please enter a new (unique) identifer and secret.');
			}
			else
			{
				$content = ['client_grants' => Repositories\GrantRepository::AUTHORIZATION_CODE.','.Repositories\GrantRepository::REFRESH_TOKEN];
			}
			unset($content['client_secret']);
		}
		else
		{
			$button = key($content['button']);
			unset($content['button']);
			switch($button)
			{
				case 'save':
				case 'apply':
				case 'delete':
					try {
						$cmd = new AdminCmds\Client([
							'update' => $content['client_id'],
						]+(array)$content['admin_cmd']+($button === 'delete' ? [
							'active' => false,
						] : [
							'identifier' => $content['client_identifier'],
							'name'   => $content['client_name'],
							'secret' => $content['client_secret'],
							'grants' => $content['client_grants'],
							'scopes' => $content['client_scopes'],
							'active' => $content['client_status'],
							'redirect_uri' => $content['client_redirect_uri'],
						]));

						$content['msg'] = $cmd->run();
						$content['client_id'] = $cmd->client_id;

						Api\Framework::refresh_opener($content['msg'], self::APP, $content['client_id']);
						if ($button !== 'apply') Api\Framework::window_close();
					}
					catch (\Exception $ex) {
						$content['msg'] = lang('Error').': '.$ex->getMessage();
					}
					break;
			}
		}
		$sel_options = [
			'client_status' => [
				1 => 'Active',
				0 => 'Disabled',
			],
			'client_grants' => Repositories\GrantRepository::selOptions(true),
			'client_scopes' => (new Repositories\ScopeRepository())->selOptions(),
		];
		$tpl = new Api\Etemplate('openid.client');
		// secret/password is required to create new clients
		if (empty($content['client_id']))
		{
			$tpl->setElementAttribute('client_secret', 'needed', true);
		}
		$tpl->exec(self::APP.'.'.__CLASS__.'.'.__FUNCTION__, $content, $sel_options, [], [
			'client_id' => $content['client_id'],
		], 2);
	}

	/**
	 * Query clients for nextmatch widget
	 *
	 * @param array $query with keys 'start', 'search', 'order', 'sort', 'col_filter'
	 *	For other keys like 'filter', 'cat_id' you have to reimplement this method in a derived class.
	 * @param array &$rows returned rows/competitions
	 * @param array &$readonlys eg. to disable buttons based on acl, not use here, maybe in a derived class
	 * @return int number of rows found
	 */
	public function getClients(array $query, array &$rows, array &$readonlys)
	{
		if (($ret = $this->clientRepo->get_rows($query, $rows, $readonlys)))
		{
			foreach($rows as $key => &$row)
			{
				if (!is_int($key)) continue;

				// boolean does NOT work as key for select-box
				$row['client_status'] = (string)(int)$row['client_status'];
				$row['client_scopes'] = (string)$row['client_scopes'];
			}
		}
		return $ret;
	}

	/**
	 * Display list of clients
	 *
	 * @param array $_content =null
	 */
	public function clients(array $_content=null)
	{
		if (is_array($_content))
		{
			foreach($_content['nm']['selected'] as $client_id)
			{
				try {
					switch($_content['nm']['action'])
					{
						case 'delete':
							$cmd = new AdminCmds\Client([
								'update' => $client_id,
								'active' => false,
							]);
							$msg = $cmd->run();
							break;
					}
				}
				catch(\Exception $e) {
					$msg = lang('Error').': '.$e->getMessage();
					break;
				}
			}
			// prefix msg with number of selected
			if (count($_content['nm']['selected']) > 1 &&
				strpos($msg, lang('Error')) !== 0)
			{
				$msg = count($_content['nm']['selected']).' '.$msg;
			}
		}
		$content = [
			'msg' => $msg,
			'nm' => [
				'get_rows' => self::APP.'.'.__CLASS__.'.getClients',
				'no_cat' => true,
				'no_filter' => true,
				'no_filter2' => true,
				'filter_no_lang' => true,
				'order' => 'client_updated',
				'sort' => 'DESC',
				'row_id' => 'client_id',
				'default_cols' => '!client_id',
				'actions' => self::clientActions(),
			]
		];
		$sel_options = [
			'client_status' => ['Disabled', 'Active'],
			'client_grants' => Repositories\GrantRepository::selOptions(true),
			'client_scopes' => (new Repositories\ScopeRepository())->selOptions()+['' => 'All'],
		];
		$tpl = new Api\Etemplate('openid.clients');
		$tpl->exec(self::APP.'.'.__CLASS__.'.'.__FUNCTION__, $content, $sel_options);
	}

	/**
	 * Return actions for cup list
	 *
	 * @return array
	 */
	static protected function clientActions()
	{
		$actions =array(
			'edit' => array(
				'caption' => 'Edit',
				'default' => true,
				'allowOnMultiple' => false,
				'url' => 'menuaction='.self::APP.'.'.__CLASS__.'.client&client_id=$id',
				'popup' => '600x450',
				'group' => $group=0,
			),
			'add' => array(
				'caption' => 'Add',
				'url' => 'menuaction='.self::APP.'.'.__CLASS__.'.client',
				'popup' => '600x420',
				'group' => $group,
			),
			'copy' => array(
				'caption' => 'Copy',
				'url' => 'menuaction='.self::APP.'.'.__CLASS__.'.client&copy=$id',
				'popup' => '600x420',
				'allowOnMultiple' => false,
				'group' => $group,
			),
			'delete' => array(
				'caption' => 'Disable',
				'allowOnMultiple' => true,
				'confirm' => 'Disable this client',
				'group' => $group=5,
			),
		);

		return $actions;
	}

	/**
	 * Hook to build admin and sidebox menu
	 *
	 * @param string|array $args hook args
	 */
	static public function menu($args)
	{
		$location = is_array($args) ? $args['location'] : $args;

		$file['Clients'] = Api\Egw::link('/index.php','menuaction='.self::APP.'.'.__CLASS__.'.clients&ajax=true');

		switch ($location)
		{
			case 'sidebox_menu':
				display_sidebox(self::APP, lang('OpenID / OAuth2 Server'), $file);
				break;

			case 'admin':
				display_section(self::APP, $file);
				break;
		}
	}
}