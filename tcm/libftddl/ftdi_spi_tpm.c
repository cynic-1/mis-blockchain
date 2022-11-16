#include <stdio.h>
#include <string.h>
#include <time.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "SpiDriver.h"
#include "ftdi_spi_tpm.h"

//static  struct mpsse_context* mpsse_;
static  unsigned locality_;   // Set at initialization.
static int debug_level;

typedef unsigned char u08;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s08;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

// int port = 0;
//int bitrate  = 10000;
int mode = 0;
int bitorder = 0;
u32 length;

stDI spidev = { "/dev/spi",-1,-1 };

// Assorted TPM2 registers for interface type FIFO.
#define TPM_REG_BASE			0xd40000

#define TPM_ACCESS_REG    		(TPM_REG_BASE + locality_ * 0x1000 + 0x0)
#define TPM_STS_REG       		(TPM_REG_BASE + locality_ * 0x1000 + 0x18)
#define TPM_DATA_FIFO_REG 		(TPM_REG_BASE + locality_ * 0x1000 + 0x80)
#define TPM_DID_VID_REG   		(TPM_REG_BASE + locality_ * 0x1000 + 0xf00)
#define TPM_RID_REG       		(TPM_REG_BASE + locality_ * 0x1000 + 0xf04)

// Locality management bits (in TPM_ACCESS_REG)
enum TpmAccessBits {
	tpmRegValidSts = (1 << 7),
	activeLocality = (1 << 5),
	requestUse = (1 << 1),
	tpmEstablishment = (1 << 0),
};

enum TpmStsBits {
	tpmFamilyShift = 26,
	tpmFamilyMask = ((1 << 2) - 1),  // 2 bits wide
	tpmFamilyTPM2 = 1,
	resetEstablishmentBit = (1 << 25),
	commandCancel = (1 << 24),
	burstCountShift = 8,
	burstCountMask = ((1 << 16) - 1),  // 16 bits wide
	stsValid = (1 << 7),
	commandReady = (1 << 6),
	tpmGo = (1 << 5),
	dataAvail = (1 << 4),
	Expect = (1 << 3),
	selfTestDone = (1 << 2),
	responseRetry = (1 << 1),
};

// SPI frame header for TPM transactions is 4 bytes in size, it is described
// in section "6.4.6 Spi Bit Protocol" of the TCG issued "TPM Profile (PTP)
// Specification Revision 00.43.
typedef struct {
	unsigned char body[4];
} SpiFrameHeader;

void FtdiStop(void) {
	CloseSPI(spidev);
}

static void StartTransaction(int read_write, size_t bytes, unsigned addr)
{
//	unsigned char *response;
	SpiFrameHeader header;
	int i;
	//usleep(100000);
	//usleep(10000);  // give it 10 ms. TODO(vbendeb): remove this once
					// cr50 SPS TPM driver performance is fixed.

	// The first byte of the frame header encodes the transaction type (read or
	// write) and size (set to lenth - 1).
	header.body[0] = (read_write ? 0x80 : 0) | 0x40 | (bytes - 1);

	// The rest of the frame header is the internal address in the TPM
	for (i = 0; i < 3; i++)
		header.body[i + 1] = (addr >> (8 * (2 - i))) & 0xff;

	//Start(mpsse_);

	//response = Transfer(mpsse_, header.body, sizeof(header.body));
	/*response =*/ ch_spi_transfer(spidev, header.body, sizeof(header.body));

	// The TCG TPM over SPI specification itroduces the notion of SPI flow
	// control (Section "6.4.5 Flow Control" of the TCG issued "TPM Profile
	// (PTP) Specification Revision 00.43).

	// The slave (TPM device) expects each transaction to start with a 4 byte
	// header trasmitted by master. If the slave needs to stall the transaction,
	// it sets the MOSI bit to 0 during the last clock of the 4 byte header. In
	// this case the master is supposed to start polling the line, byte at time,
	// until the last bit in the received byte (transferred during the last
	// clock of the byte) is set to 1.
	/*
	while (!(response[3] & 1)) {
	  unsigned char *poll_state;
	  //poll_state = Read(mpsse_, 1);
	  poll_state = ch_spi_read(handle, 1);
	  response[3] = *poll_state;
	  free(poll_state);
	}
	*/
// 	free(response);
}

static void trace_dump(const char *prefix, unsigned reg, size_t bytes, const uint8_t *buffer)
{
	static char prev_prefix;
	static unsigned prev_reg;
	static int current_line;

	if (!debug_level)
		return;

	if ((debug_level < 2) && (reg != TPM_DATA_FIFO_REG))
		return;

	if ((prev_prefix != *prefix) || (prev_reg != reg)) {
		prev_prefix = *prefix;
		prev_reg = reg;
		printf("\n%s %2.2x:", prefix, reg);
		current_line = 0;
	}

	if ((reg != TPM_DATA_FIFO_REG) && (bytes == 4)) {
		printf(" %8.8x", *(const uint32_t*)buffer);
	}
	else {
		int i;
		for (i = 0; i < bytes; i++) {
			if (current_line && !(current_line % BYTES_PER_LINE)) {
				printf("\n     ");
				current_line = 0;
			}
			current_line++;
			printf(" %2.2x", buffer[i]);
		}
	}
}

static int FtdiWriteReg(unsigned reg_number, size_t bytes, void *buffer)
{
	//if (!mpsse_)
	//  return false;
	trace_dump("W", reg_number, bytes, buffer);
	StartTransaction(false, bytes, reg_number);
	//Write(mpsse_, buffer, bytes);
	ch_spi_write(spidev, buffer, bytes);
	//Stop(mpsse_);
	return true;
}

static int FtdiReadReg(unsigned reg_number, size_t bytes, void *buffer)
{
	unsigned char *value;
	//if (!mpsse_)
	//  return false;
	printf("\n\rDebug1 %s  0x%08X\n\r", spidev.name, spidev.handle);
	StartTransaction(true, bytes, reg_number);
	//value = Read(mpsse_, bytes);
	printf("\n\rDebug2 %s  0x%08X\n\r", spidev.name, spidev.handle);
	value = ch_spi_read(spidev, bytes);
	if (buffer)
		memcpy(buffer, value, bytes);
// 	free(value);
	//Stop(mpsse_);    
	trace_dump("R", reg_number, bytes, buffer);
	return true;
}

unsigned long WriteTPMRegister(unsigned long addr, unsigned long rlen, unsigned char *indata)
{
	unsigned char *value;
	unsigned char rvalue[128] = { 0 };
	SpiFrameHeader header;
	int i;
	char readen = false;

	header.body[0] = (unsigned char)((readen ? 0x80 : 0) | 0x40 | (rlen - 1));
	for (i = 0; i < 3; i++)
		header.body[i + 1] = (addr >> (8 * (2 - i))) & 0xff;
	value = (unsigned char *)malloc(rlen + 4);
	for (i = 0; i < 4; i++)
		value[i] = header.body[i];
	memcpy(value + 4, indata, rlen);
// 	SetSpiChipSelect(spidev, EM_SPICS0, false, true);
// 	WriteSpiData(spidev, (char *)value, rlen + 4, 1);
// 	SetSpiChipSelect(spidev, EM_SPICS0, false, false);
	ReadWriteSpiData(spidev.handle, value, rlen + 4, rvalue, 0);

	free(value);
	return true;
}
unsigned long ReadTPMRegister(unsigned long addr, unsigned long rlen, unsigned char *outdata)
{
	unsigned char *value;
	unsigned char rvalue[4096] = { 0 };
	SpiFrameHeader header;
	unsigned long i;
	char readen = true;

	header.body[0] = (unsigned char)((readen ? 0x80 : 0) | 0x40 | (rlen - 1));
	for (i = 0; i < 3; i++)
		header.body[i + 1] = (addr >> (8 * (2 - i))) & 0xff;

	value = (unsigned char *)malloc(rlen + 4);
	for (i = 0; i < 4; i++)
		value[i] = header.body[i];

	for (i = 4; i < (rlen + 4); i++)
		value[i] = 0x00;

// 	SetSpiChipSelect(spidev, EM_SPICS0, false, true);
// 	WriteSpiData(spidev, (char *)value, rlen + 4, 8);
// 	SetSpiChipSelect(spidev, EM_SPICS0, false, false);
// 	SetSpiChipSelect(spidev, EM_SPICS0, false, true);
// 	ReadSpiData(spidev, (char *)value, rlen + 4, 8);
// 	SetSpiChipSelect(spidev, EM_SPICS0, false, false);
	ReadWriteSpiData(spidev.handle, value, rlen + 4,rvalue, rlen + 4);

	memcpy(outdata, &rvalue[4], rlen);

	free(value);
	return true;
}

static int ReadTpmSts(uint32_t *status)
{
	return ReadTPMRegister(TPM_STS_REG, sizeof(*status), (unsigned char *)status);
}

static int WriteTpmSts(uint32_t status)
{
	return WriteTPMRegister(TPM_STS_REG, sizeof(status), (unsigned char *)&status);
}

static uint32_t GetBurstCount(void)
{
	uint32_t status;

	ReadTpmSts(&status);
	return (status >> burstCountShift) & burstCountMask;
}

//int FtdiSpiInit(uint32_t freq, int enable_debug) {
int FtdiSpiInit(stDI dev,unsigned int bitrate, int enable_debug) {

	uint32_t did_vid, status;
	uint8_t cmd;
	uint16_t vid;

	debug_level = enable_debug;

	/**************************************
	*						HANDLE init
	**************************************/
	spidev = OpenSPI(dev, bitrate);

	if (spidev.handle == -1) {
		printf("Unable to open PCIe device\r\n");
		printf("Error handle = %d; device name = %s\r\n", spidev.handle,spidev.handle?spidev.name:"NULL");
		return false;
	}
	//printf("Starting %s at %dHZ\n\r",spidev.name, (int)bitrate);

	fflush(stdout);

	ReadTPMRegister(TPM_DID_VID_REG, sizeof(did_vid), (unsigned char*)&did_vid);
	vid = did_vid & 0xffff;
	if ((vid != 0x1b4e) && (vid != 0x1050)) {
		fprintf(stderr, "unknown did_vid: %#x\n", did_vid);
		return false;
	}

	// Try claiming locality zero.
	ReadTPMRegister(TPM_ACCESS_REG, sizeof(cmd), &cmd);
	if ((cmd & (activeLocality & tpmRegValidSts)) ==
		(activeLocality & tpmRegValidSts)) {
		/*
		 * Locality active - maybe reset line is not connected?
		 * Release the locality and try again
		 */
		cmd = activeLocality;
		WriteTPMRegister(TPM_ACCESS_REG, sizeof(cmd), &cmd);
		ReadTPMRegister(TPM_ACCESS_REG, sizeof(cmd), &cmd);
	}
	// tpmEstablishment can be either set or not.
	if ((cmd & ~(tpmEstablishment | activeLocality)) != tpmRegValidSts) {
		fprintf(stderr, "invalid reset status: %#x\n", cmd);
		return false;
	}
	cmd = requestUse;
	WriteTPMRegister(TPM_ACCESS_REG, sizeof(cmd), &cmd);
	ReadTPMRegister(TPM_ACCESS_REG, sizeof(cmd), &cmd);
	if ((cmd &  ~tpmEstablishment) != (tpmRegValidSts | activeLocality)) {
		fprintf(stderr, "failed to claim locality, status: %#x\n", cmd);
		return false;
	}

	ReadTpmSts(&status);
	if (((status >> tpmFamilyShift) & tpmFamilyMask) != tpmFamilyTPM2) {
		fprintf(stderr, "unexpected TPM family value, status: %#x\n", status);
		return false;
	}
	ReadTPMRegister(TPM_RID_REG, sizeof(cmd), &cmd);
	//printf("Connected to device vid:did:rid of %4.4x:%4.4x:%2.2x\n", did_vid & 0xffff, did_vid >> 16, cmd);

	return true;
}

/* This is in seconds. */
#define MAX_STATUS_TIMEOUT 120
static int WaitForStatus(uint32_t statusMask, uint32_t statusExpected)
{
	uint32_t status;
	time_t target_time;
	static unsigned max_timeout;

	target_time = time(NULL) + MAX_STATUS_TIMEOUT;
	do {
		//usleep(10000);
		//usleep(100000);
		if (time(NULL) >= target_time) {
			fprintf(stderr, "failed to get expected status %x\n", statusExpected);
			return false;
		}
		ReadTpmSts(&status);
	} while ((status & statusMask) != statusExpected);

	/* Calculate time spent waiting */
	target_time = MAX_STATUS_TIMEOUT - target_time + time(NULL);
	if (max_timeout < (unsigned)target_time) {
		max_timeout = target_time;
		//printf("\nNew max timeout: %d s\n", max_timeout);
	}

	return true;
}

static void SpinSpinner(void)
{
	static const char *spinner = "\\|/-";
	static int index;

	if (index > strlen(spinner))
		index = 0;
	/* 8 is the code for 'cursor left' */
	//fprintf(stdout, "%c%c", 8, spinner[index++]);
	//fflush(stdout);
}

#define MAX_RESPONSE_SIZE 4096
#define HEADER_SIZE 6
unsigned char debugbuf[4096] = { 0 };
/* tpm_command points at a buffer 4096 bytes in size */
size_t FtdiSendCommandAndWait(uint8_t *tpm_command, size_t command_size)
{
	uint32_t status;
	uint32_t expected_status_bits;
	size_t handled_so_far;
	uint32_t payload_size;
	char message[100];
	int offset = 0;

	handled_so_far = 0;

	WriteTpmSts(commandReady);
	
	expected_status_bits = commandReady;
	if (!WaitForStatus(expected_status_bits, expected_status_bits)) {
		size_t i;

		printf("Failed processing. %s:", message);
		for (i = 0; i < command_size; i++) {
			if (!(i % 16))
				printf("\n");
			printf(" %2.2x", tpm_command[i]);
		}
		printf("\n");
		return 0;
	}

	memcpy(&payload_size, tpm_command + 2, sizeof(payload_size));
	payload_size = SwapByte(payload_size, 4);

	offset += snprintf(message, sizeof(message), "Message size %d", payload_size);
	//showdata((unsigned char *)(tpm_command), payload_size, 16);

	// No need to wait for the sts.Expect bit to be set, at least with the
	// 15d1:001b device, let's just write the command into FIFO, make sure not
	// to exceed the burst count.
	do {
		uint32_t transaction_size;
		uint32_t burst_count = GetBurstCount();

		if (burst_count > 4)
			burst_count = 4;

		transaction_size = command_size - handled_so_far;
		if (transaction_size > burst_count)
			transaction_size = burst_count;

		if (transaction_size) {
// 			FtdiWriteReg(TPM_DATA_FIFO_REG, transaction_size, tpm_command + handled_so_far);
			memset(debugbuf, 0, sizeof(debugbuf));
			WriteTPMRegister(TPM_DATA_FIFO_REG, transaction_size, (unsigned char *)(tpm_command + handled_so_far));
			handled_so_far += transaction_size;
		}
	} while (handled_so_far != command_size);


	// And tell the device it can start processing it.
	WriteTpmSts(tpmGo);

	expected_status_bits = stsValid | dataAvail;
	if (!WaitForStatus(expected_status_bits, expected_status_bits)) {
		size_t i;

		printf("Failed processing. %s:", message);
		for (i = 0; i < command_size; i++) {
			if (!(i % 16))
				printf("\n");
			printf(" %2.2x", tpm_command[i]);
		}
		printf("\n");
		return 0;
	}

	// The tpm_command is ready, let's read it.
	// First we read the FIFO payload header, to see how much data to expect.
	// The header size is fixed to six bytes, the total payload size is stored
	// in network order in the last four bytes of the header.

	// Let's read the header first.
	ReadTPMRegister(TPM_DATA_FIFO_REG, 2, tpm_command);

	ReadTPMRegister(TPM_DATA_FIFO_REG, 4, &tpm_command[2]);

	//ReadTPMRegister(TPM_DATA_FIFO_REG, HEADER_SIZE, tpm_command);
	handled_so_far = HEADER_SIZE;
	//showdata(tpm_command, HEADER_SIZE, 16);
	// Figure out the total payload size.
	memcpy(&payload_size, tpm_command + 2, sizeof(payload_size));
	//payload_size = ntohl(payload_size);
	//payload_size = be32toh(payload_size);
	payload_size = SwapByte(payload_size, 4);

//	showdata(tpm_command, payload_size, 16);
	if (!debug_level)
		SpinSpinner();

	if (payload_size > MAX_RESPONSE_SIZE)
		return 0;

	// Let's read all but the last byte in the FIFO to make sure the status
	// register is showing correct flow control bits: 'more data' until the last
	// byte and then 'no more data' once the last byte is read.
	payload_size = payload_size - 1;
	do {
		uint32_t transaction_size;
		uint32_t burst_count = GetBurstCount();

		if (burst_count > 4)
			burst_count = 4;

		transaction_size = payload_size - handled_so_far;
		if (transaction_size > burst_count)
			transaction_size = burst_count;

		if (transaction_size) {
			ReadTPMRegister(TPM_DATA_FIFO_REG, transaction_size, tpm_command + handled_so_far);
			handled_so_far += transaction_size;
		}
	} while (handled_so_far != payload_size);

	// Verify that there is still data to come.
	ReadTpmSts(&status);
	if ((status & expected_status_bits) != expected_status_bits) {
		fprintf(stderr, "unexpected status %#x\n", status);
		return 0;
	}

	ReadTPMRegister(TPM_DATA_FIFO_REG, 1, tpm_command + handled_so_far);

	// Verify that 'data available' is not asseretd any more.
	ReadTpmSts(&status);
	if ((status & expected_status_bits) != stsValid) {
		fprintf(stderr, "unexpected status %#x\n", status);
		return 0;
	}

	/* Move the TPM back to idle state. */
	WriteTpmSts(commandReady);

	return handled_so_far + 1;
}

/**
	*SwapByte
	*/
unsigned long SwapByte(unsigned long src, char type)
{
	unsigned long temp = 0;
	char *psrc = (char *)&src;
	char *pthis = (char *)&temp;

	if (type == 2)
	{
		pthis[0] = psrc[1];
		pthis[1] = psrc[0];
	}
	if (type == 4)
	{
		pthis[0] = psrc[3];
		pthis[1] = psrc[2];
		pthis[2] = psrc[1];
		pthis[3] = psrc[0];
	}
	return temp;
}

/**
	*	ch_spi_write
	*/
int ch_spi_write(stDI dev, void* vdata, int size)
{
	uint8_t* data = vdata;
	uint8_t* buf = NULL;
	int retval = -1;
	buf = malloc(size);
	if (buf)
		memset(buf, 0, size);
	ReadWriteSpiData(dev.handle, (unsigned char*)data, size, buf, 0);
	free(buf);
	retval = 0;
	return retval;
}

uint8_t grxbuf[4096] = { 0 };
/**
	*	ch_spi_read
	*/
unsigned char* ch_spi_read(stDI dev, int size)
{
	memset(grxbuf, 0, size);
	ReadWriteSpiData(dev.handle, grxbuf, size, grxbuf, 0);

	return grxbuf;
}

/**
	*	ch_spi_transfer
	*/
uint8_t* ch_spi_transfer(stDI dev, uint8_t* data, int size)
{
	memset(grxbuf, 0, size);
	ReadWriteSpiData(dev.handle, data, size, grxbuf, size);

	return grxbuf;
}
