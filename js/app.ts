/**
 * EGroupware OpenIDConnect
 *
 * @package openid
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb@egroupware.org>
 * @license https://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

import {EgwApp} from '../../api/js/jsapi/egw_app';
import {app} from "../../api/js/jsapi/egw_global";
import type {etemplate2} from "../../api/js/etemplate/etemplate2";
import type {AdminApp} from "../../admin/js/app";

/**
 * UI for OpenIDConnect
 */
export class OpenIDConnectApp extends EgwApp
{
	et2_ready(et2: etemplate2, name: string)
	{
		super.et2_ready(et2, name);

		switch (name)
		{
			case 'openid.clients':
				(<AdminApp>app.admin)?.enableAppToolbar(et2, name);
				break;
		}
	}
}

// Register the app with EGroupware
app.classes.openid = OpenIDConnectApp;