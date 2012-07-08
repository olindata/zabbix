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

#include "log.h"
#include "mutexs.h"
#include "memalloc.h"
#include "ipc.h"
#include "zbxauthcache.h"
#include "zbxalgo.h"

#define	LOCK_AUTH_CACHE		zbx_mutex_lock(&authcache_lock)
#define	UNLOCK_AUTH_CACHE	zbx_mutex_unlock(&authcache_lock)
#define	AUTH_SESSION_TIMEOUT	360  /* in seconds */

static zbx_hashset_t	*authcache_sessions = NULL;
static zbx_mem_info_t	*authcache_mem;
static ZBX_MUTEX	authcache_lock;

ZBX_MEM_FUNC_IMPL(__authcache, authcache_mem);

typedef struct {
	zbx_uint64_t	hostid;
	zbx_auth_state_t auth_state;
	int		last_access;
}
ZBX_AC_SESSION;

#ifdef HAVE_GSASL

static ZBX_AC_SESSION *get_auth_session(zbx_uint64_t hostid);

/******************************************************************************
 *                                                                            *
 * Function: init_auth_cache                                                  *
 *                                                                            *
 * Purpose: Allocate shared memory for authentication sessions.               *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	init_auth_cache()
{
	const char	*__function_name = "init_auth_cache";
	size_t		authcache_size;
	key_t		shm_key;
	int		rc;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() size:%d", __function_name, AUTH_CACHE_SIZE);

	authcache_size = AUTH_CACHE_SIZE;

	if (-1 == (shm_key = zbx_ftok(CONFIG_FILE, ZBX_IPC_AUTHCACHE_ID)))
	{
		zbx_error("Can't create IPC key for configuration cache");
		exit(FAIL);
	}

	if (ZBX_MUTEX_ERROR == zbx_mutex_create_force(&authcache_lock, ZBX_MUTEX_AUTHCACHE))
	{
		zbx_error("cannot create mutex for authentication cache");
		exit(FAIL);
	}

	zbx_mem_create(&authcache_mem, shm_key, ZBX_NO_MUTEX, authcache_size, "authentication cache", "AuthCacheSize");

	authcache_sessions = __authcache_mem_malloc_func(NULL, sizeof(zbx_hashset_t));

#define	INIT_HASHSET_SIZE	1000

	zbx_hashset_create_ext(authcache_sessions, INIT_HASHSET_SIZE,
			ZBX_DEFAULT_UINT64_HASH_FUNC, ZBX_DEFAULT_UINT64_COMPARE_FUNC,
			__authcache_mem_malloc_func, __authcache_mem_realloc_func,
			__authcache_mem_free_func);

#undef	INIT_HASHSET_SIZE

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Function: free_auth_cache                                                  *
 *                                                                            *
 * Purpose: Release shared memory for authentication sessions.                *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
void	free_auth_cache()
{
	const char		*__function_name = "free_auth_cache";
	zbx_hashset_iter_t	iter;
	ZBX_AC_SESSION		*session;

	LOCK_AUTH_CACHE;

	zbx_hashset_destroy(authcache_sessions);
	zbx_mem_destroy(authcache_mem);

	UNLOCK_AUTH_CACHE;

	zbx_mutex_destroy(&authcache_lock);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
}


/******************************************************************************
 *                                                                            *
 * Function: ACupdate_auth_state                                              *
 *                                                                            *
 * Purpose: Update the authentication state of the host.                      *
 *                                                                            *
 * Parameters: hostid - [IN] The host id                                      *
 *             state - [IN] The authentication state                          *
 *                                                                            *
 * Return value:  SUCCEED - host is authenticated                             *
 *                FAIL - an error occurred or host is not authenticated       *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	ACupdate_auth_state(zbx_uint64_t hostid, zbx_auth_state_t state)
{
	const char	*__function_name = "ACupdate_auth_state";
	ZBX_AC_SESSION	*session;
	int		res = SUCCEED;

	LOCK_AUTH_CACHE;

	session = get_auth_session(hostid);
	zabbix_log(LOG_LEVEL_DEBUG,
		"In %s() hostid: " ZBX_FS_UI64 " state: %d newstate: %d",
		__function_name, hostid, session->auth_state, state);

	switch(state)
	{
	case AUTH_STATE_NOT_AUTH:
	case AUTH_STATE_FAILED:
		session->auth_state = state;
		session->last_access = -1;
		break;
	case AUTH_STATE_AUTHENTICATED:
		session->auth_state = state;
		session->last_access = time(NULL);
		break;
	default:
		zabbix_log(LOG_LEVEL_WARNING, "Invalid auth state received");
		res = FAIL;
	}

	UNLOCK_AUTH_CACHE;

	return res;
}

/******************************************************************************
 *                                                                            *
 * Function: ACis_authenticated                                               *
 *                                                                            *
 * Purpose: Check whether the host is already authenticated.                  *
 *                                                                            *
 * Parameters: hostid - The host id                                           *
 *                                                                            *
 * Return value:  SUCCEED - host is authenticated                             *
 *                FAIL - an error occurred or host is not authenticated       *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	ACis_authenticated(zbx_uint64_t hostid)
{
	const char	*__function_name = "ACis_authenticated";
	ZBX_AC_SESSION	*session;
	int		res = FAIL;

	session = get_auth_session(hostid);

	zabbix_log(LOG_LEVEL_DEBUG,
		"In %s() hostid: " ZBX_FS_UI64 " state: %d lastaccess: %d",
		__function_name, hostid, session->auth_state, session->last_access);

	if(session->auth_state == AUTH_STATE_AUTHENTICATED)
	{
		if ((session->last_access + AUTH_SESSION_TIMEOUT) > time(NULL))
		{
			res = SUCCEED;
		}
		else
		{
			ACupdate_auth_state(hostid, AUTH_STATE_NOT_AUTH);
		}
	}

	return res;
}

/******************************************************************************
 *                                                                            *
 * Function: ACrefresh_last_access                                            *
 *                                                                            *
 * Purpose: Refresh the last access time of an authenticated host.            *
 *                                                                            *
 * Parameters: hostid - The host id                                           *
 *                                                                            *
 * Return value:  SUCCEED - The last access time of the host is updated       *
 *                FAIL - an error occurred or host is not authenticated       *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	ACrefresh_last_access(zbx_uint64_t hostid)
{
	const char	*__function_name = "ACrefresh_last_access";
	ZBX_AC_SESSION	*session;
	int		res = FAIL;

	session = get_auth_session(hostid);

	zabbix_log(LOG_LEVEL_DEBUG,
		"In %s() hostid: " ZBX_FS_UI64 " state: %d lastaccess: %d",
		__function_name, hostid, session->auth_state, session->last_access);

	if(
		session->auth_state == AUTH_STATE_AUTHENTICATED &&
		(session->last_access + AUTH_SESSION_TIMEOUT) > time(NULL)
	) {
		session->last_access = time(NULL);
		res = SUCCEED;
	}

	return res;
}

/******************************************************************************
 *                                                                            *
 * Function: get_auth_session                                                 *
 *                                                                            *
 * Purpose: find existing or add new structure and return pointer             *
 *                                                                            *
 * Return value: pointer to a authentication session structure                *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
static ZBX_AC_SESSION *get_auth_session(zbx_uint64_t hostid)
{
	const char	*__function_name = "get_auth_session";
	ZBX_AC_SESSION	*ptr = NULL, session;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hostid: " ZBX_FS_UI64, __function_name, hostid);
	if (NULL != (ptr = (ZBX_AC_SESSION *)zbx_hashset_search(authcache_sessions, &hostid)))
		return ptr;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() creating session for hostid: " ZBX_FS_UI64, __function_name, hostid);
	memset(&session, 0, sizeof(ZBX_AC_SESSION));
	session.hostid = hostid;

	return (ZBX_AC_SESSION *)zbx_hashset_insert(authcache_sessions, &session, sizeof(ZBX_AC_SESSION));
}
#endif
