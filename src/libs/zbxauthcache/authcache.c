#include "zbxauthcache.h"

/******************************************************************************
 *                                                                            *
 * Function: init_auth_cache                                                  *
 *                                                                            *
 * Purpose: Allocate shared memory for authentication sessions.               *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
void	init_auth_cache()
{
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
}

/******************************************************************************
 *                                                                            *
 * Function: get_auth_session                                                 *
 *                                                                            *
 * Purpose: Gets the host's authentication session object.                    *
 *                                                                            *
 * Parameters: hostid - The host id                                           *
 *                                                                            *
 * Return value: pointer to a GSASL session structure                         *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
Gsasl_session *get_auth_session(zbx_uint64_t hostid)
{
    return NULL;
}

/******************************************************************************
 *                                                                            *
 * Function: set_auth_session                                                 *
 *                                                                            *
 * Purpose: Sets the host's authentication session object.                    *
 *                                                                            *
 * Parameters: hostid - The host id                                           *
 *             session - The GSASL authentication session structure           *
 *                                                                            *
 * Return value:  SUCCEED - session object is set                             *
 *                FAIL - an error occurred or session object cannot be set    *
 *                                                                            *
 * Author: Seh Hui Leong                                                      *
 *                                                                            *
 ******************************************************************************/
int	set_auth_session(zbx_uint64_t hostid, Gsasl_session *session)
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
