#include "zbxauthcache.h"

static Gsasl		*ctx = NULL;
static const char	*mech =	"SCRAM-SHA-1";

#define	LOCK_AUTH_CACHE		zbx_mutex_lock(&auth_cache_lock)
#define	UNLOCK_AUTHCACHE	zbx_mutex_unlock(&auth_cache_lock)

static ZBX_MUTEX	auth_cache_lock;
static zbx_hashset_t	auth_sessions;

typedef enum {
	NOT_AUTH = 0,
	HANDSHAKE,
	AUTHENTICATED,
	FAILED		/* 4 */

}
ZBX_AC_AUTH_STATE;

typedef struct {
	zbx_uint64_t	hostid;
	Gsasl_session	*session;
	ZBX_AC_AUTH_STATE authenticated;
	int		last_access;
	int		timeout;
}
ZBX_AC_SESSION;

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
	int	rc;

	if((rc = gsasl_init(&ctx)) != GSASL_OK) {
		return FAIL;
	}
#define	INIT_HASHSET_SIZE	1000	/* should be calculated dynamically based on trends size? */

	zbx_hashset_create(&auth_sessions, INIT_HASHSET_SIZE,
			ZBX_DEFAULT_UINT64_HASH_FUNC, ZBX_DEFAULT_UINT64_COMPARE_FUNC);

#undef	INIT_HASHSET_SIZE

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
	/**
	 * TODO: I may need to iterate this through and free up all the GSASL
	 * sessions.
	 */
	zbx_hashset_destroy(&auth_sessions);
	gsasl_done(ctx);
}

/******************************************************************************
 *                                                                            *
 * Function: init_session                                                     *
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
int	init_session(zbx_uint64_t hostid, char *handshake_msg, char *challenge)
{
	return NULL;
}

/******************************************************************************
 *                                                                            *
 * Function: authenticate                                                     *
 *                                                                            *
 * Purpose: Receives the client's response to the authentication challenge    *
 *          and authenticate the client based on the password on the DB.      *
 *                                                                            *
 * Parameters: hostid - [IN] The host id                                      *
 *             challenge_resp - [IN] The client's response to the server's    *
 *                              challenge                                     *
 *             auth_status - [OUT] SUCCEED if the client is authenticated;    *
 *                                 FAIL if the client failed the challenge.   *
 *             auth_resp - [OUT] The server's response after authentication.  *
 *                                                                            *
 * Return value:  SUCCEED - The client is authenticated.                      *
 *                FAIL - an error occurred or session object cannot be set    *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	authenticate(zbx_uint64_t hostid, char *challenge_resp,
		int *auth_status, char *auth_resp)
{
	return 0;
}

/******************************************************************************
 *                                                                            *
 * Function: check_auth_session                                               *
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
int	check_auth_status(zbx_uint64_t hostid)
{
	return 0;
}
