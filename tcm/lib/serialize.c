#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "tcmfunc.h"

uint32_t TCM_ReadFile(const char * filename, unsigned char ** buffer, uint32_t * buffersize)
{
	uint32_t ret = 0;
	struct stat _stat;
	if (0 == stat(filename, &_stat)) {
		*buffer = (unsigned char *)malloc(_stat.st_size);
		*buffersize = (uint32_t)_stat.st_size;
		if (NULL != *buffer) {
			FILE * f = fopen(filename, "rb");
			if (NULL != f) {
				if ((size_t)_stat.st_size != fread(*buffer, 1, _stat.st_size, f)) {
					free(*buffer);
					*buffer = NULL;
					*buffersize = 0;
					ret = -1;
				}
				if (fclose(f) != 0)
					ret = -1;
			} else {
				free(*buffer);
				*buffersize = 0;
				ret = -1;
			}
		} else {
			ret = -1;
		}
	} else {
		ret = -1;
	}	
	return ret;
}

uint32_t TCM_WriteFile(const char * filename, unsigned char * buffer, uint32_t buffersize)
{
	uint32_t ret = 0;
	if (buffer == NULL) {
		return -1;
	}
	FILE * f = fopen(filename, "wb");
	if (NULL != f) {
		if (buffersize != fwrite(buffer, 1, buffersize,f)) {
			ret =  -1;
		}
		if (fclose(f) != 0)
			ret =  -1;
	} else {
		ret =  -1;
	}

	return ret;
}
