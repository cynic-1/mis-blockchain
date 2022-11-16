#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmfunc.h>
#include <tcmutil.h>
#include <ap.h>
#include <tcmalg.h>
#include <tcm_structures.h>
#include <tcmkeys.h>

/****************************************************************************/
/*                                                                          */
/*  GetCapability                                                           */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_GetCapability(uint32_t type, uint32_t subtype_length, uint8_t* subtype)
{
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_GetCapability;
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L L @",&tcmdata,
	                             ordinal_no, type, subtype_length, subtype);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"GetCapability");
	
	// todo: parse return values
	
	tcm_buffer_load32(&tcmdata, 6, &ret);		
	return ret;
}