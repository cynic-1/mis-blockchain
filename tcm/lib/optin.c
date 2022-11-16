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

uint32_t TCM_PhysicalEnable()
{
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_PhysicalEnable;
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L",&tcmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"PhysicalEnable");

	if (ret == 0 && tcmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	return ret;
}

uint32_t TCM_PhysicalSetDeactivated(TCM_BOOL state)
{
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_PhysicalSetDeactivated;
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L o",&tcmdata,
	                             ordinal_no,
	                               state);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"PhysicalSetDeactivated");

	if (ret == 0 && tcmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	return ret;
}