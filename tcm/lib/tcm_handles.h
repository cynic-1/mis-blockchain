#ifndef _TCM_HANDLES_H_
#define _TCM_HANDLES_H_

#include "tcm_structures.h"

/*
 * definition of an invalid handle
 */ 
#define TCM_INVALID_HANDLE             0xFFFFFFFF

/*
 * macros to convert array indices to handles
 */
#define INDEX_TO_KEY_HANDLE(i)         ((i) | (TCM_RT_KEY << 24))

TCM_KEY_DATA *tcm_get_key(TCM_KEY_HANDLE handle);


TCM_SESSION_DATA *tcm_get_auth(TCM_AUTHHANDLE handle);

#endif /* _TCM_HANDLES_ */
