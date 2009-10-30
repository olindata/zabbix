<?php
/*
** ZABBIX
** Copyright (C) 2000-2009 SIA Zabbix
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**/
?>
<?php
/**
 * File containing CAPIInfo class for API.
 * @package API
 */
/**
 * Class containing methods for operations with APIInfo
 */
class CAPIInfo extends CZBXAPI{
/**
 * Get API version
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @return string 
 */
	public static function version(){
		return ZABBIX_API_VERSION;
	}

}
?>
