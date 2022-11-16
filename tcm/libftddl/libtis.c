#include <stdio.h>
#include <string.h>
#include <time.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "ftdi_spi_tpm.h"
#include "libtis.h"

char spidevname[]="./spidev.ini";

TSS_RESULT Tddli_TransmitData(	BYTE* in, 
								UINT32 insize, 
								BYTE* out, 
								UINT32* outsize)
{	
	BYTE buffer[MAX_BUFFER_SIZE];
		
	memcpy(buffer, in, insize);
	*outsize = FtdiSendCommandAndWait(buffer, insize);
	memcpy(out, buffer, *outsize);
	
	return 0;
}

TSS_RESULT  Tddli_Open()
{
	int bitrate = 42000000;
	int enable_debug = 0;
	int fmaxlen,flen,tmplen,i,j;
	char *pthis,temp[32] = {0};
	FILE  	*infile;
	//open file
	infile = fopen(spidevname, "rb");
	if (infile == NULL)
	{
		printf("Error: Open %s Failed or file does not exist\n\r", spidevname);
		return -1;
	}
	fseek(infile, 0, SEEK_END);
	fmaxlen = ftell(infile);
	fseek(infile, 0, SEEK_SET);
	rewind(infile);

	pthis = (char *)malloc(fmaxlen);
	memset(pthis,0,fmaxlen);
	tmplen = sizeof("spidev[0]:") - 1;
	fseek(infile, tmplen, SEEK_SET);

	flen = fread(pthis, 1, fmaxlen, infile);
	fclose(infile);
	if ((flen == 0) || (flen > fmaxlen))
		return -1;
	memset(spidev.name, '\0', sizeof(spidev.name));
	for(i = 0,j = 0;pthis[i] != ':';j++)
	{
		spidev.name[j]=pthis[i++];
	}
	bitrate = 0;
	memset(temp, '\0', sizeof(temp));
	for(j = 0,i++;pthis[i] != ':';j++)
	{
		temp[j]=pthis[i++];
	}
	if(j > sizeof(temp))
	{
		printf("speed value invalid\n\r");
		return 1;
	}
	bitrate = atoi(temp);
	memset(temp, '\0', sizeof(temp));
	for(j = 0,i++;pthis[i] != '\n';j++)
	{
		temp[j]=pthis[i++];
	}
	if(j > sizeof(temp))
	{
		printf("enable_debug value invalid\n\r");
		return 1;
	}
	enable_debug = atoi(temp);
	//printf("%s@%d->enable_debug: %d\n\r",spidev.name,bitrate,enable_debug);
	if (FtdiSpiInit(spidev,bitrate, enable_debug) == 0)
		return 1;
	free(pthis);
	return 0;
}

TSS_RESULT Tddli_Close()
{
	FtdiStop();
	return 0;
}

