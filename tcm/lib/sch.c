#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm.h"
#include "ap.h"
#include "tcm_structures.h"

uint32_t TCM_SCHStart(uint32_t* max)
{
    uint32_t ret=0;
    uint32_t ordinal = TCM_ORD_SCHStart;
    STACK_TCM_BUFFER(tcmdata)
   	
    ret = TSS_buildbuff("00 C1 T L",&tcmdata,ordinal);
    if ((ret & ERR_MASK) != 0 ) return ret;
    ret = TCM_Transmit(&tcmdata,"SCHStart");
    if (ret != 0) return ret;
    STORE32(tcmdata.buffer, 6, ret);
    if(ret == 0 ) tcm_buffer_load32(&tcmdata,TCM_DATA_OFFSET,max);
    return ret;
}

uint32_t TCM_SCHUpdate(unsigned char * data,uint32_t len)
{
    uint32_t ret=0;
    uint32_t ordinal = TCM_ORD_SCHUpdate;
    STACK_TCM_BUFFER(tcmdata)
   	
    ret = TSS_buildbuff("00 C1 T L L %",&tcmdata,ordinal,len,len,data);
    if ((ret & ERR_MASK) != 0 ) return ret;
    ret = TCM_Transmit(&tcmdata,"SCHUpdate");
    if (ret != 0) return ret;
    STORE32(tcmdata.buffer, 6, ret);

    return ret;
}

uint32_t TCM_SCHComplete(unsigned char * data,uint32_t len,unsigned char * digest)
{
    uint32_t ret=0;
    uint32_t ordinal = TCM_ORD_SCHComplete;
    STACK_TCM_BUFFER(tcmdata)
   	
    ret = TSS_buildbuff("00 C1 T L L %",&tcmdata,ordinal,len,len,data);
    if ((ret & ERR_MASK) != 0 ) return ret;
    ret = TCM_Transmit(&tcmdata,"SCHComplete");
    if (ret != 0) return ret;
    STORE32(tcmdata.buffer, 6, ret);
    if(ret == 0 ) 
        memcpy(digest, &tcmdata.buffer[TCM_DATA_OFFSET],32);
    return ret;
}




