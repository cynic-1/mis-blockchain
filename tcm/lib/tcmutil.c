#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
//#include <unistd.h>     

#ifdef TCM_POSIX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif

//#include <openssl/rand.h>
#include "tcm_structures.h"
#include "tcmalg.h"
#include "tcm.h"
#include "tcmfunc.h"
#include "tcmutil.h"
#include "libtddl.h"
//#include "FILE.h"

static unsigned int logflag = 1;

int  TSS_sm3(unsigned char * passwd, unsigned int len, unsigned char authvalue[32]){
	return tcm_sch_hash(len, passwd, authvalue);
}

/****************************************************************************/
/*                                                                          */
/* Generate a random nonce                                                  */
/*                                                                          */
/****************************************************************************/
int TSS_tcmgennonce(unsigned char *nonce)
{
    //return RAND_bytes(nonce,TCM_HASH_SIZE);
	/* alternative solution for non openssl */
	 int randomData = open("/dev/random", O_RDONLY);
	char myRandomData[TCM_HASH_SIZE];
	size_t randomDataLen = 0;
	while (randomDataLen < sizeof myRandomData)
	{
		size_t result = read(randomData, myRandomData + randomDataLen, (sizeof myRandomData) - randomDataLen);
		if (result < 0)
		{
			// error, unable to read /dev/random 
		}
		randomDataLen += result;
	}
	close(randomData);

	memcpy(nonce, myRandomData, TCM_HASH_SIZE);
	return 0;
}

/****************************************************************************/
/*									  */
/* Perform a SCH hash on a file					    */
/*									  */
/****************************************************************************/
uint32_t TSS_SCHFile(const char *filename, unsigned char *buffer)
{
	uint32_t ret = 0;
	FILE *f;
	f = fopen(filename, "r");
	
	if (NULL != f) {
		size_t len;
		unsigned char mybuffer[10240];
		sch_context ctx;
		tcm_sch_starts(&ctx);		
		do {
			len = fread(mybuffer, 1, sizeof(mybuffer), f);
			if (len) {
				tcm_sch_update(&ctx, mybuffer, len);				
			}
		} while (len == sizeof(mybuffer));
		fclose(f);
		tcm_sch_finish(&ctx, buffer);		
	} else {
		ret = ERR_BAD_FILE;
	}
	return ret;
}

/****************************************************************************/
/*                                                                          */
/*  This routine takes a format string, sort of analogous to sprintf,       */
/*  a buffer, and a variable number of arguments, and copies the arguments  */
/*  and data from the format string into the buffer, based on the characters*/
/*  in the format string.                                                   */
/*                                                                          */
/*  The routine returns a negative value if it detects an error in the      */
/*  format string, or a positive value containing the total length          */
/*  of the data copied to the buffer.                                       */
/*                                                                          */
/*  The legal characters in the format string are...                        */
/*                                                                          */
/*  0123456789abcdefABCDEF                                                  */
/*     These are used to insert bytes directly into the buffer, represented */
/*     in the format string as hex ASCII.  These MUST be in pairs,          */
/*     representing the two hex nibbles in a byte. e.g. C3 would insert     */
/*     a byte containing the hex value 0xC3 next position in the buffer.    */
/*     There is no argument associated with these format characters.        */
/*                                                                          */
/*  L                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NETWORK byte order (big endian)      */
/*                                                                          */
/*  S                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NETWORK byte order (big endian)     */
/*                                                                          */
/*                                                                          */
/*  l                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NATIVE byte order.                   */
/*                                                                          */
/*  s                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NATIVE byte order.                  */
/*                                                                          */
/*  o                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     byte or character                                                    */
/*                                                                          */
/*  @                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 32 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  ^  This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 16 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  %                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is NOT inserted into the buffer.                          */
/*                                                                          */
/*  T                                                                       */
/*     This is used to insert a 4 byte long value (32 bits, big endian)     */
/*     containing the total length of the data inserted into the buffer.    */
/*     There is no argument associated with this format character.          */
/*                                                                          */
/*                                                                          */
/*  Example                                                                 */
/*                                                                          */
/*   buildbuff("03Ts@99%",buf,10,6,"ABCDEF",3,"123");                       */
/*                                                                          */
/*   would produce a buffer containing...                                   */
/*                                                                          */
/*                                                                          */
/*   03 00 00 00 15 00 0A 00 00 00 06 41 42 43 44 45 46 99 31 32 33         */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
int TSS_buildbuff(char *format,struct tcm_buffer *tb, ...)
{
    unsigned char *totpos;
    va_list argp;
    char *p;
    unsigned int totlen;
    unsigned char *o;
    unsigned long l;
    unsigned short s;
    unsigned char c;
    unsigned long len;
    uint16_t len16;
    unsigned char byte = 0;
    unsigned char hexflag;
    unsigned char *ptr;
    unsigned char *buffer = tb->buffer;
    unsigned int start = tb->used;
    int dummy;
   
    va_start(argp,tb);
    totpos = 0;
    totlen = tb->used;
    o = &buffer[totlen];
    hexflag = 0;
    p = format;
    while (*p != '\0')
	{
	    switch (*p)
		{
		  case ' ':
		    break;
		  case 'L':
		  case 'X':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    l = (unsigned long)va_arg(argp,unsigned long);
		    STORE32(o,0,l);
		    if (*p == 'X')
		            va_arg(argp, unsigned long);
		    o += 4;
		    totlen += TCM_U32_SIZE;
		    break;
		  case 'S':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 2 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    s = (unsigned short)va_arg(argp,int);
		    STORE16(o,0,s);
		    o += TCM_U16_SIZE;
		    totlen += TCM_U16_SIZE;
		    break;
		  case 'l':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    l = (unsigned long)va_arg(argp,unsigned long);
		    STORE32N(o,0,l);
		    o += TCM_U32_SIZE;
		    totlen += TCM_U32_SIZE;
		    break;
		  case 's':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 2 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    s = (unsigned short)va_arg(argp,int);
		    STORE16N(o,0,s);
		    o += TCM_U16_SIZE;
		    totlen += TCM_U16_SIZE;
		    break;
		  case 'o':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    c = (unsigned char)va_arg(argp,int);
		    *(o) = c;
		    o += 1;
		    totlen += 1;
		    break;
		  case '@':
		  case '*':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = (int)va_arg(argp,int);
		    if (totlen + 4 + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TCM_U32_SIZE;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += len + TCM_U32_SIZE;
		    break;
		  case '&':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len16 = (uint16_t)va_arg(argp,int);
		    if (totlen + 2 + len16 >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE16(o,0,len16);
		    o += TCM_U16_SIZE;
		    if (len16 > 0) memcpy(o,ptr,len16);
		    o += len16;
		    totlen += len16 + TCM_U16_SIZE;
		    break;
		  case '%':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = (int)va_arg(argp,int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += len;
		    break;
		  case 'T':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    totpos = o;
		    o += TCM_U32_SIZE;
		    totlen += TCM_U32_SIZE;
		    break;
		  case '0':
		  case '1':
		  case '2':
		  case '3':
		  case '4':
		  case '5':
		  case '6':
		  case '7':
		  case '8':
		  case '9':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  ((*p - '0') & 0x0F);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case 'A':
		  case 'B':
		  case 'C':
		  case 'D':
		  case 'E':
		  case 'F':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  (((*p - 'A') & 0x0F) + 0x0A);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case 'a':
		  case 'b':
		  case 'c':
		  case 'd':
		  case 'e':
		  case 'f':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  (((*p - 'a') & 0x0F) + 0x0A);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case '^': 
		            /* the size indicator is only 16 bits long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len16 = (uint16_t)va_arg(argp, int);
		    dummy = va_arg(argp, int);
		    dummy = dummy; /* make compiler happy */
		    if (totlen + len16 >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE16(o,0,len16);
		    o += TCM_U16_SIZE;
		    if (len16 > 0) memcpy(o,ptr,len16);
		    o += len16;
		    totlen += TCM_U16_SIZE + len16;
		    break;
		  case '!': 
		            /* the size indicator is 32 bytes long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = va_arg(argp,int);
		    dummy = va_arg(argp, int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TCM_U32_SIZE;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += TCM_U32_SIZE + len;
		    break;
		  case '#': 
		            /* reverse write the buffer (good for 'exponent') */
		            /* the size indicator is 32 bytes long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = va_arg(argp,int);
		    dummy = va_arg(argp, int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TCM_U32_SIZE;
		    totlen += TCM_U32_SIZE + len;
		    while (len > 0) {
		        *o = ptr[len-1];
		        o++;
		        len--;
		    }
		    break;
		  default:
		    return ERR_BAD_ARG;
		}
	    ++p;
	}
    if (totpos != 0) STORE32(totpos,0,totlen);
    va_end(argp);
#ifdef DEBUG_BUILDBUFF
    printf("buildbuff results...\n");
    size_t i;
	for (i = 0;=0; i < totlen; i++)
	{
	    if (i && !( i % 16 ))
		{
		    printf("\n");
		}
	    printf("%.2X ",buffer[i]);
	}
    printf("\n");
#endif
    tb->used = totlen;
    return totlen-start;
}

/****************************************************************************/
/*									  */
/* Transmit request to TCM and read Response				*/
/*									  */
/****************************************************************************/

uint32_t TCM_SPI_Open() {
	return Tddli_Open();
}

uint32_t TCM_SPI_Transmit(BYTE* in, uint32_t insize, BYTE* out, uint32_t *outsize){
	return Tddli_TransmitData(in, insize, out, outsize);
}

uint32_t TCM_SPI_Close(){
	return Tddli_Close();
}

static uint32_t TCM_Transmit_Internal(struct tcm_buffer *tb,const char *msg,
                                      int allowTransport)
{
    uint32_t rc = 0;
	BYTE * indata;
	BYTE outdata[TCM_MAX_BUFF_SIZE];
	int readlen = 0;

	indata = tb->buffer;
	if(logflag == 1){
		printf(" ==================================\n ");
		printf(" *****TCM transmit input command %s*****\n ", msg);
		printf(" input length: %d\n",tb->used);
		size_t i;
		for (i = 0; i < tb->used; i++)
		{
			printf("%02x ", indata[i]);
			if (i > 0 && (i + 1) % 16 == 0)
			{
				printf("\n");
			}
			
		}
		printf("\n");
		
	}
	TCM_SPI_Open();
	TCM_SPI_Transmit(indata, tb->used, outdata, &readlen);
	TCM_SPI_Close();
	memcpy(tb->buffer, outdata, readlen);
	tb->used = readlen;

	if(logflag == 1){
		printf(" *****TCM transmit output*****\n ");
		printf(" output length: %d\n", readlen);
		size_t i;
		for (i = 0; i < readlen; i++)
		{
			printf("%02x ", outdata[i]);
			if (i > 0 && (i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");
		printf(" ==================================\n ");
	}
    return rc;
}


uint32_t TCM_Transmit(struct tcm_buffer *tb,const char *msg)
{
    return TCM_Transmit_Internal(tb, msg, 1);
}

uint32_t tcm_buffer_load32(const struct tcm_buffer *tb, uint32_t off, uint32_t *val)
{
	if (off + 3 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD32(tb->buffer, off);
	return 0;
}

uint32_t tcm_buffer_store32(struct tcm_buffer *tb, uint32_t val)
{
	if (tb->used + 4 > tb->size) {
		return ERR_BUFFER;
	}
	STORE32(tb->buffer, tb->used, val);
	tb->used += 4;
	return 0;
}

uint32_t tcm_buffer_load32N(const struct tcm_buffer *tb, uint32_t off, uint32_t *val)
{
	if (off + 3 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD32N(tb->buffer, off);
	return 0;
}

uint32_t tcm_buffer_load16(const struct tcm_buffer *tb, uint32_t off, uint16_t *val)
{
	if (off + 1 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD16(tb->buffer, off);
	return 0;
}

uint32_t tcm_buffer_load16N(const struct tcm_buffer *tb, uint32_t off, uint16_t *val)
{
	if (off + 1 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD16N(tb->buffer, off);
	return 0;
}



/****************************************************************************/
/*									  */
/* set logging flag							 */
/*									  */
/****************************************************************************/
int TCM_setlog(int flag)
{
	int old;
	char *dump = getenv("TCM_DUMP_COMMANDS");
	
	old = logflag;
	/* user has control if TCM_DUMP_COMMANDS == "0" */
	if (NULL == dump || strcmp(dump,"0") == 0)
		logflag = flag;
	return old;
}

/****************************************************************************/
/*                                                                          */
/*  Convert Error code to message                                           */
/*                                                                          */
/****************************************************************************/
static char *msgs[] = {
   "Unknown error"                                      ,
   "Authentication failed (Incorrect Password)"         ,
   "Illegal index"                                      ,
   "Bad parameter"                                      ,
   "Auditing failure"                                   ,
   "Clear disabled"                                     ,
   "TCM deactivated"                                    ,
   "TCM disabled"                                       ,
   "Target command disabled"                            ,
   "Operation failed"                                   ,
   "Ordinal unknown"                                    ,
   "Owner installation disabled"                        ,
   "Invalid key handle"                                 ,
   "Target key not found"                               ,
   "Unacceptable encryption scheme"                     ,
   "Migration authorization failed"                     ,
   "PCR information incorrect"                          ,
   "No room to load key"                                ,
   "No SRK set"                                         ,
   "Encrypted blob invalid"                             ,
   "TCM already has owner"                              ,
   "TCM out of resources"                               ,
   "Random string too short"                            ,
   "TCM out of space"                                   ,
   "PCR mismatch"                                       ,
   "Paramsize mismatch"                                 ,
   "No existing SHA-1 thread"                           ,
   "SHA-1 thread error"                                 ,
   "TCM self test failed - TCM shutdown"                ,
   "Authorization failure for 2nd key"                  ,
   "Invalid tag value"                                  ,
   "TCM I/O error"                                      ,
   "Encryption error"                                   ,
   "Decryption failure"                                 ,
   "Invalid handle"                                     ,
   "TCM has no endorsement key"                         ,
   "Invalid key usage"                                  ,
   "Invalid entity type"                                ,
   "Incorrect command sequence"                         ,
   "Inappropriate signature data"                       ,
   "Unsupported key properties"                         ,
   "Incorrect migration properties"                     ,
   "Incorrect signature or encryption scheme"           ,
   "Incorrect data size"                                ,
   "Incorrect mode parameter"                           ,
   "Invalid presence values"                            ,
   "Incorrect version"                                  ,
   "No support for wrapped transports"                  ,
   "Audit construction failed, command unsuccessful"    ,
   "Audit construction failed, command successful"      ,
   "Not resetable"                                      ,
   "Missing locality information"                       ,
   "Incorrect type"                                     ,
   "Invalid resource"                                   ,
   "Not in FIPS mode"                                   ,
   "Invalid family"                                     ,
   "No NV permission"                                   ,
   "Requires signed command"                            ,
   "Key not supported"                                  ,
   "Authentication conflict"                            ,
   "NV area is locked"                                  ,
   "Bad locality"                                       ,
   "NV area is read-only"                               ,
   "No protection on write into NV area"                ,
   "Family count value does not match"                  ,
   "NV area is write locked"                            ,
   "Bad NV area attributes"                             ,
   "Invalid structure"                                  ,
   "Key under control by owner"                         ,
   "Bad counter handle"                                 ,
   "Not full write"                                     ,
   "Context GAP"                                        ,
   "Exceeded max NV writes without owner"               ,
   "No operator authorization value set"                ,
   "Resource missing"                                    ,
   "Delegate administration is locked"                  ,
   "Wrong delegate family"                              ,
   "Delegation management not enabled"                  ,
   "Command executed outside transport session"         ,
   "Key is under control of owner"                      ,
   "No DAA resources available"                         ,
   "InputData0 is inconsistent"                         ,
   "InputData1 is inconsistent"                         ,
   "DAA: Issuer settings are not consistent"            ,
   "DAA: TCM settings are not consistent"               ,
   "DAA stage failure"                                  ,
   "DAA: Issuer validity check detected inconsistency"  ,
   "DAA: Wrong 'w'"                                     ,
   "Bad handle"                                         ,
   "No room for context"                                ,
   "Bad context"                                        ,
   "Too many contexts"                                  ,
   "Migration authority signature failure"              ,
   "Migration destination not authenticated"            ,
   "Migration source incorrect"                         ,
   "Migration authority incorrect"			,
   "No error description"				,
   "Attempt to revoke the EK and the EK is not revocable",
   "Bad signature of CMK ticket"			,
   "There is no room in the context list for additional contexts",
   };

static char *msgs_nonfatal[] = {
    "Retry"						,
    "Needs self test"					,
    "Doing self test"					,
    "Defend lock running"
};

static char *msgs2[] = {
   "HMAC authorization verification failed"             ,
   "NULL argument"                                      ,
   "Invalid argument"                                   ,
   "Error from OpenSSL library"                         ,
   "I/O error"                                          ,
   "Memory allocation error"                            ,
   "File error"                                         ,
   "Data in stream are bad"                             ,
   "Too many data"                                      ,
   "Buffer too small"                                   ,
   "Incorrect structure type"                           ,
   "Searched item could not be found"                   ,
   "Environment variable not set"                       ,
   "No transport allowed for this ordinal"              ,
   "Bad tag in response message"                        ,
   "Incorrect signature"                                ,
   "PCR value list does not correspond to IMA value list",
   "Checksum verification failed"                       ,
   "Format error in TCM response"                       ,
   "Choice of session type is bad"                      ,
   "Failure during close()/fclose()"                    ,
   "File write error"                                   ,
   "File read error"                                    ,
   };
   
char *TCM_GetErrMsg(uint32_t code)
   {
   if (code  >= ERR_HMAC_FAIL &&
       code  <  ERR_LAST) {
       return msgs2[code - ERR_HMAC_FAIL];
   }

   if ((code > 0) && (code < 100)) {
       return msgs[code];
   }
   if ((code >= TCM_NON_FATAL) &&
       (code < (TCM_NON_FATAL + 4))) {
       if ((code & 0xff) == 0) {
	   printf("\n\n\nRETRY error code\n\n\n");
       }
       return msgs_nonfatal[code - TCM_NON_FATAL];
   }
   return msgs[0];
   }
