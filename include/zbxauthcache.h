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

extern char	*CONFIG_FILE;
extern int	AUTH_CACHE_SIZE;

int	init_auth_cache();
void	free_auth_cache();
int	ACupdate_auth_state(zbx_uint64_t hostid, zbx_auth_state_t state);
int	ACis_authenticated(zbx_uint64_t hostid);
int	ACrefresh_last_access(zbx_uint64_t hostid);

#endif
#endif

