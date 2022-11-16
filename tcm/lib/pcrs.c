#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm.h"
#include "ap.h"
#include "tcm_structures.h"

uint32_t TCM_PcrRead(uint32_t pcrIndex, unsigned char *pcrvalue)
{
   uint32_t ret;
   uint32_t ordinal = TCM_ORD_PcrRead;
   STACK_TCM_BUFFER(tcmdata)
   	
   if (pcrvalue == NULL) return ERR_NULL_ARG;
   ret = TSS_buildbuff("00 C1 T L L",&tcmdata,ordinal, pcrIndex);
   if ((ret & ERR_MASK) != 0 ) return ret;
   ret = TCM_Transmit(&tcmdata,"PCRRead");
   if (ret != 0) return ret;
   memcpy(pcrvalue,&tcmdata.buffer[TCM_DATA_OFFSET],TCM_HASH_SIZE);
   return 0;
}

uint32_t TCM_Extend(uint32_t pcrIndex,
                    unsigned char * event,
                    unsigned char * outDigest) {
	uint32_t ret;
	uint32_t ordinal = TCM_ORD_Extend;	
	STACK_TCM_BUFFER(tcmdata)

  if (outDigest == NULL) return ERR_NULL_ARG;
	ret = TSS_buildbuff("00 C1 T L L %",&tcmdata, ordinal, pcrIndex, TCM_HASH_SIZE, event);
	if ((ret & ERR_MASK) != 0 ) return ret;
	ret = TCM_Transmit(&tcmdata,"Extend");
	if (ret != 0) return ret;
 	memcpy(outDigest, &tcmdata.buffer[TCM_DATA_OFFSET], TCM_HASH_SIZE);	
	return 0;
}

uint32_t TCM_PcrReset(uint32_t pcrIndex)
{
   uint32_t ret;
   uint32_t ordinal = TCM_ORD_PcrReset;
   STACK_TCM_BUFFER(tcmdata)

   TCM_PCR_SELECTION pcrselection;
   pcrselection.sizeOfSelect = 0x0003;
   pcrselection.pcrSelect[0] = 0x01;
   pcrselection.pcrSelect[1] = 0x01;
   pcrselection.pcrSelect[2] = 0x01;
   if(pcrIndex < 8)
   {
      pcrselection.pcrSelect[0] <<= pcrIndex;
      pcrselection.pcrSelect[1] = 0x00;
      pcrselection.pcrSelect[2] = 0x00;
   }
   else if((pcrIndex > 7) && (pcrIndex < 16))
   {
      pcrselection.pcrSelect[0] = 0x00;
      pcrselection.pcrSelect[1] <<= (pcrIndex - 8);
      pcrselection.pcrSelect[2] = 0x00;
   }
   else if((pcrIndex > 15) && (pcrIndex < 24))
   {
      pcrselection.pcrSelect[0] = 0x00;
      pcrselection.pcrSelect[1] = 0x00;
      pcrselection.pcrSelect[2] <<= (pcrIndex - 16);
   }
   else
   {
      return ERR_PCR_LIST_NOT_IMA;
   }

   ret = TSS_buildbuff("00 C1 T L S o o o",&tcmdata, ordinal, pcrselection.sizeOfSelect, pcrselection.pcrSelect[0], pcrselection.pcrSelect[1], pcrselection.pcrSelect[2]);
   if ((ret & ERR_MASK) != 0 ) return ret;
   ret = TCM_Transmit(&tcmdata,"PCRReset");
   if (ret != 0) return ret;
   return 0;
}

uint32_t TCM_PcrExtend(uint32_t pcrIndex, unsigned char *pcrvalue)
{
   uint32_t ret;
   uint32_t ordinal = TCM_ORD_Extend;
   STACK_TCM_BUFFER(tcmdata)

   if (pcrvalue == NULL) return ERR_NULL_ARG;
   ret = TSS_buildbuff("00 C1 T L L %",&tcmdata,ordinal, pcrIndex, TCM_HASH_SIZE, pcrvalue);
   if ((ret & ERR_MASK) != 0 ) return ret;
   ret = TCM_Transmit(&tcmdata,"PcrExtend");
   if (ret != 0) return ret;
   memcpy(pcrvalue,&tcmdata.buffer[TCM_DATA_OFFSET],TCM_HASH_SIZE);
   return 0;
}

