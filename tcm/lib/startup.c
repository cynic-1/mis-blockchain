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

uint32_t TCM_Startup()
{
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_Startup;
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L 00 01",&tcmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"Startup");
	
	STORE32(tcmdata.buffer, 6, ret);
	
	return ret;
}
