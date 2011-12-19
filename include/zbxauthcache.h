#ifndef ZABBIX_ZBXAUTHCACHE_H
#define ZABBIX_ZBXAUTHCACHE_H

#include "common.h"
#include "config.h"

#ifdef HAVE_GSASL
int	init_auth_cache();
void	free_auth_cache();
Gsasl_session *get_auth_session(zbx_uint64_t hostid);
int	set_auth_session(zbx_uint64_t hostid, Gsasl_session *session);
int	check_auth_status();

#endif
#endif

