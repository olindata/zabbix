#ifndef ZABBIX_ZBXAUTHCACHE_H
#define ZABBIX_ZBXAUTHCACHE_H

/*
#include "common.h"
#include "config.h"
*/

#ifdef HAVE_GSASL
int	init_auth_cache();
void	free_auth_cache();
int	init_session(zbx_uint64_t hostid, char *handshake_msg,
		char *challenge);
int	authenticate(zbx_uint64_t hostid, char *challenge_resp,
		int *auth_status, char *auth_resp);
int	check_auth_status();

#endif
#endif

