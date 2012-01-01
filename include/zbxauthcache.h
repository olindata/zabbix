/*
** Zabbix
** Copyright (C) 2000-2011 Zabbix SIA
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
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#ifndef ZABBIX_ZBXAUTHCACHE_H
#define ZABBIX_ZBXAUTHCACHE_H

#include "common.h"

#ifdef HAVE_GSASL
int	init_auth_cache();
void	free_auth_cache();
int	ACinit_session(zbx_uint64_t hostid, char *handshake_msg,
		char *challenge);
int	ACauthenticate(zbx_uint64_t hostid, char *stored_password,
		char *challenge_resp, zbx_auth_state_t *auth_status,
		char *auth_resp);
int	ACis_authenticated(zbx_uint64_t hostid);

#endif
#endif

