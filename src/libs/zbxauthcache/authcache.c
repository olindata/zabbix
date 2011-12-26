#include "log.h"
#include "mutexs.h"
#include "zbxauthcache.h"
#include "zbxalgo.h"

static Gsasl		*ctx = NULL;
static const char	*mech =	"SCRAM-SHA-1";

#define	LOCK_AUTH_CACHE		zbx_mutex_lock(&auth_cache_lock)
#define	UNLOCK_AUTH_CACHE	zbx_mutex_unlock(&auth_cache_lock)
#define AUTH_SESSION_TIMEOUT	360  // in seconds

static ZBX_MUTEX	auth_cache_lock;
static zbx_hashset_t	auth_sessions;

typedef struct {
	zbx_uint64_t	hostid;
	Gsasl_session	*session;
	zbx_auth_state_t auth_state;
	int		auth_enabled;
	int		last_access;
}
ZBX_AC_SESSION;

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
	const char	*__function_name = "ACinit_auth_cache";
	int		rc;

	if((rc = gsasl_init(&ctx)) != GSASL_OK) {
		return FAIL;
	}

	if (ZBX_MUTEX_ERROR == zbx_mutex_create_force(&auth_cache_lock, ZBX_MUTEX_CACHE))
	{
		zbx_error("cannot create mutex for authentication cache");
		exit(FAIL);
	}

#define	INIT_HASHSET_SIZE	1000	/* should be calculated dynamically based on trends size? */

	zbx_hashset_create(&auth_sessions, INIT_HASHSET_SIZE,
			ZBX_DEFAULT_UINT64_HASH_FUNC, ZBX_DEFAULT_UINT64_COMPARE_FUNC);

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
	const char		*__function_name = "ACfree_auth_cache";
	zbx_hashset_iter_t	iter;
	ZBX_AC_SESSION		*session;

	LOCK_AUTH_CACHE;

	/* Clear off all session instances from memory */
	zbx_hashset_iter_reset(&auth_sessions, &iter);
	while (NULL != (session = (ZBX_AC_SESSION *)zbx_hashset_iter_next(&iter))) {
		gsasl_finish(session->session);
	}
	zbx_hashset_destroy(&auth_sessions);

	UNLOCK_AUTH_CACHE;

	zbx_mutex_destroy(&auth_cache_lock);
	gsasl_done(ctx);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
}

/******************************************************************************
 *                                                                            *
 * Function: ACinit_session                                                     *
 *                                                                            *
 * Purpose: Initializes the client's authentication session.                  *
 *                                                                            *
 * Parameters: hostid - [IN] The host id                                      *
 *             handshake_msg - [IN] The handshake message from the client.    *
 *             challenge - [OUT] The challenge issued from the server.        *
 *                                                                            *
 * Return value: SUCCEED - An authentication session is initiated             *
 *               FAIL - An error occurred or the session cannot be initiated  *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	ACinit_session(zbx_uint64_t hostid, char *handshake_msg, char *challenge)
{
	const char	*__function_name = "ACinit_session";
	ZBX_AC_SESSION	*session;
	char		buf[BUFSIZ] = "";

	LOCK_AUTH_CACHE;

	session = get_auth_session(hostid);

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hostid: " ZBX_FS_UI64 " state: %d", __function_name, hostid, session->auth_state);

	/* If the user has a pre-existing session, reset the authentication
	 * states
	 */
	if(
		session->auth_state != AUTH_STATE_NOT_AUTH ||
		session->auth_state != AUTH_STATE_FAILED
	) {
		session->auth_state = AUTH_STATE_NOT_AUTH;
		gsasl_finish(session->session);
	}

	if(gsasl_server_start(ctx, mech, &session->session) != GSASL_OK) {
		return FAIL;
	}
	if(gsasl_step64(session->session, handshake_msg, &buf) != GSASL_NEEDS_MORE) {
		return FAIL;
	}

	/* Once a valid handshake is received, return a challenge */
	session->auth_state = AUTH_STATE_HANDSHAKE;
	challenge = buf;

	UNLOCK_AUTH_CACHE;

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Function: ACauthenticate                                                     *
 *                                                                            *
 * Purpose: Receives the client's response to the authentication challenge    *
 *          and authenticate the client based on the password on the DB.      *
 *                                                                            *
 * Parameters: hostid - [IN] The host id                                      *
 *             stored password - [IN] The password stored in the server's DB  *
 *             challenge_resp - [IN] The client's response to the server's    *
 *                              challenge                                     *
 *             auth_state - [OUT] The authentication state the host is in     *
 *             auth_resp - [OUT] The server's response after authentication.  *
 *                                                                            *
 * Return value:  SUCCEED - The client is authenticated.                      *
 *                FAIL - an error occurred or session object cannot be set    *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	ACauthenticate(zbx_uint64_t hostid, char *stored_password,
        char *challenge_resp, zbx_auth_state_t *auth_state, char *auth_resp)
{
	const char	*__function_name = "ACauthenticate";
	ZBX_AC_SESSION	*session;
	char		buf[BUFSIZ] = "";

	LOCK_AUTH_CACHE;

	/* If the user has a pre-existing session, reset the authentication
	 * states
	 */
	session = get_auth_session(hostid);

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hostid: " ZBX_FS_UI64 " state: %d", __function_name, hostid, session->auth_state);

	if(session->auth_state != AUTH_STATE_HANDSHAKE) {
		return FAIL;
	}

	gsasl_property_set(session->session, GSASL_PASSWORD, stored_password);
	if(gsasl_step64(session->session, challenge_resp, &buf) != GSASL_OK) {
		gsasl_finish(session->session);
		session->auth_state = AUTH_STATE_FAILED;
		return FAIL;
	}

	session->auth_state = AUTH_STATE_AUTHENTICATED;
	session->last_access = time(NULL);

	UNLOCK_AUTH_CACHE;

	return SUCCEED;
}

/******************************************************************************
 *                                                                            *
 * Function: ACis_authenticated
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
	const char	*__function_name = "ACauthenticate";
	ZBX_AC_SESSION	*session;
	int		res = FAIL;

	/* If the user has a pre-existing session, reset the authentication
	 * states
	 */
	session = get_auth_session(hostid);

	zabbix_log(LOG_LEVEL_DEBUG,
		"In %s() hostid: " ZBX_FS_UI64 " state: %d lastaccess: %d",
		__function_name, hostid, session->auth_state, session->last_access);

	/* TODO: Check the timeout as well */
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
	ZBX_AC_SESSION	*ptr, session;

	if (NULL != (ptr = (ZBX_AC_SESSION *)zbx_hashset_search(&auth_sessions, &hostid)))
		return ptr;

	memset(&session, 0, sizeof(ZBX_AC_SESSION));
	session.hostid = hostid;

	return (ZBX_AC_SESSION *)zbx_hashset_insert(&auth_sessions, &session, sizeof(ZBX_AC_SESSION));
}
