#ifndef ZABBIX_ZBXAUTHCACHE_H
#define ZABBIX_ZBXAUTHCACHE_H

#include "common.h"

#ifdef HAVE_GSASL
int	ACinit_auth_cache();
void	ACfree_auth_cache();
int	ACinit_session(zbx_uint64_t hostid, char *handshake_msg,
		char *challenge);
int	ACauthenticate(zbx_uint64_t hostid, char *stored_password,
		char *challenge_resp, zbx_auth_state_t *auth_status,
		char *auth_resp);
int	ACis_authenticated(zbx_uint64_t hostid);

#endif
#endif

