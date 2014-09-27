#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>


#include "cobra.h"
#include "cobraupdate.h"
#include "sha1.h"

#define MAX_SIZE		1048576
#define SECURITY_SIZE		4096

#define MCU_VERSION		0
#define FW_VERSION		0xC
#define FW_NAME			"Cobra USB Firmware 5.0"

#define SWAP32(x) ((((x) & 0xff)) << 24 | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))
#define todigit(n) (n-'0')

typedef struct
{
	uint32_t position;
	uint32_t size;
} __attribute__((packed)) TocEntry;

static uint8_t g_buf[MAX_SIZE];
static uint64_t serial;

static TocEntry toc[COBRA_TOC_NUM_ITEMS];

static uint32_t current_address = COBRA_TOC_SPI_FLASH_ADDRESS+0x1000;

static uint32_t static_sizes[COBRA_TOC_NUM_ITEMS] =
{
	0x20000,
	0x10000,
	0x10000,
	0x10000,
	0x10000
};

static void get_random(void *bfr, uint32_t size)
{
	FILE *fp;

	fp = fopen("/dev/urandom", "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "cannot open urandom\n");
		exit(-1);
	}

	if (fread(bfr, size, 1, fp) != 1)
	{
		fprintf(stderr, "unable to read random numbers");
		exit(-1);
	}

	fclose(fp);
}

static uint8_t get_random_byte(void)
{
	uint8_t r;
	
	get_random(&r, 1);
	return r;
}

static void SHA1(void *buf, uint16_t size, uint8_t *sha1)
{
	SHA1Context ctx;
	
	SHA1Reset(&ctx);
	SHA1Input(&ctx, buf, size);
	SHA1Result(&ctx, sha1);
}

static uint8_t nextLFSR(uint8_t LFSR)
{
	uint8_t bit0 = (LFSR&1) ^ ((LFSR >> 2)&1) ^ ((LFSR >> 3)&1) ^ ((LFSR >> 4)&1);
	LFSR = (LFSR >> 1);
	LFSR |= (bit0 << 7);
	return LFSR;
}

static int write_toc(usb_dev_handle *handle, FILE *out, SHA1Context *ctx)
{
	CobraUpdateOp operation;
	int i, ret;
	
	for (i = 0; i < COBRA_TOC_NUM_ITEMS; i++)
	{
		toc[i].position = SWAP32(toc[i].position);
		toc[i].size = SWAP32(toc[i].size);
	}
	
	memset(&operation, 0, sizeof(operation));
	operation.opcode = UPDATE_OPCODE_SPI_FLASH;
	operation.data = COBRA_TOC_SPI_FLASH_ADDRESS;
	operation.size = sizeof(toc);
	get_random(operation.dummy, sizeof(operation.dummy));
	get_random(&operation.dummy2, sizeof(operation.dummy2));
	get_random(&operation.dummy3, sizeof(operation.dummy3));
		
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_1, toc, sizeof(toc));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	SHA1(toc, sizeof(toc), operation.sha1);
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	fwrite(&operation, 1, sizeof(operation), out);
	SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
	fwrite(toc, 1, sizeof(toc), out);
	SHA1Input(ctx, (uint8_t *)toc, sizeof(toc));
	
	return 0;
}

static int write_file(usb_dev_handle *handle, FILE *in, FILE *out, int index, SHA1Context *ctx)
{
	CobraUpdateOp operation;	
	uint32_t filesize;
	int ret;	
	
	fseek(in, 0, SEEK_END);
	filesize = ftell(in);
	fseek(in, 0, SEEK_SET);	
	
	if (filesize > static_sizes[index])
	{
		printf("Error: filesize bigger than static size. Change sizes!\n");
		return -1;
	}
	
	if ((current_address+filesize) >= COBRA_SPI_FLASH_SIZE)
	{
		fprintf(stderr, "Offset+size beyond flash size (0x%x)!!!\n", current_address+filesize);
		return -1;
	}
	
	memset(&operation, 0, sizeof(operation));
	operation.opcode = UPDATE_OPCODE_SPI_FLASH;
	operation.data = current_address;
	operation.size = filesize;
	get_random(operation.dummy, sizeof(operation.dummy));
	get_random(&operation.dummy2, sizeof(operation.dummy2));
	get_random(&operation.dummy3, sizeof(operation.dummy3));
	
	if (fread(g_buf, 1, filesize, in) != filesize)
	{
		fprintf(stderr, "I/O file error.\n");
		return -1;
	}
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_1, g_buf, filesize);
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	SHA1(g_buf, filesize, operation.sha1);
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	fwrite(&operation, 1, sizeof(operation), out);
	SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
	fwrite(g_buf, 1, filesize, out);
	SHA1Input(ctx, g_buf, filesize);
	
	toc[index].position = current_address;
	toc[index].size = filesize;
	
	printf("(written to toc: 0x%x 0x%x)\n", toc[index].position, toc[index].size);
	
	current_address += static_sizes[index];
			
	fclose(in);
	return 0;
}

static int write_security(usb_dev_handle *handle, FILE *in, FILE *out, SHA1Context *ctx)
{
	CobraUpdateOp operation;
	int ret;
	
	memset(&operation, 0, sizeof(operation));
	operation.opcode = UPDATE_OPCODE_SPI_FLASH_DEC;
	operation.data = 0x8000;
	operation.size = SECURITY_SIZE;
	get_random(operation.dummy, sizeof(operation.dummy));
	get_random(&operation.dummy2, sizeof(operation.dummy2));
	get_random(&operation.dummy3, sizeof(operation.dummy3));
	
	if (fread(g_buf, 1, SECURITY_SIZE, in) != SECURITY_SIZE)
	{
		fprintf(stderr, "Security file must be 4096 bytes.\n");
		return -1;
	}
	
	SHA1(g_buf, SECURITY_SIZE, operation.sha1);
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_0, g_buf, SECURITY_SIZE);
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return -1;
	}
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return -1;
	}
	
	fwrite(&operation, 1, sizeof(operation), out);
	SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
	fwrite(g_buf, 1, SECURITY_SIZE, out);
	SHA1Input(ctx, g_buf, SECURITY_SIZE);
	
	fclose(in);
	return 0;
}

static int write_mcu(usb_dev_handle *handle, FILE *in, FILE *out, SHA1Context *ctx)
{
	CobraUpdateOp operation;
	int i, ret;
	uint8_t mcu_keys[16];
	uint8_t initLFSR, LFSR;
	
	memset(&operation, 0, sizeof(operation));	
	operation.opcode = UPDATE_OPCODE_SPI_FLASH_DEC;
	operation.data = 0;
	operation.size = COBRA_MCU_USER_PROGRAM_SIZE;
	get_random(operation.dummy, sizeof(operation.dummy));
	get_random(&operation.dummy2, sizeof(operation.dummy2));
	get_random(&operation.dummy3, sizeof(operation.dummy3));
	
	memset(g_buf, 0xFF, COBRA_MCU_USER_PROGRAM_SIZE);	
	fread(g_buf, 1, COBRA_MCU_USER_PROGRAM_SIZE, in);
	
	do
	{
		initLFSR = LFSR = get_random_byte();
	} while (LFSR == 0);
	
	for (i = 0; i < 16; i++)
	{
		mcu_keys[i] = get_random_byte();
	}
	
	for (i = 0; i < COBRA_MCU_USER_PROGRAM_SIZE; i++)
	{
		g_buf[i] = g_buf[i] ^ mcu_keys[i%16] ^ LFSR;
		LFSR = nextLFSR(LFSR);
	}
	
	SHA1(g_buf, COBRA_MCU_USER_PROGRAM_SIZE, operation.sha1);	
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	fwrite(&operation, 1, sizeof(operation), out);
	SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_0, g_buf, COBRA_MCU_USER_PROGRAM_SIZE);
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}	
	
	fwrite(g_buf, 1, COBRA_MCU_USER_PROGRAM_SIZE, out);
	SHA1Input(ctx, g_buf, COBRA_MCU_USER_PROGRAM_SIZE);
	
	memset(&operation, 0, sizeof(operation));	
	operation.opcode = UPDATE_OPCODE_START_BOOTLOADER;
	operation.data = ((initLFSR ^ 0x59) << 16) | (COBRA_MCU_USER_PROGRAM_SIZE / COBRA_MCU_PAGE_SIZE);
	operation.size = sizeof(mcu_keys);
	get_random(operation.dummy, sizeof(operation.dummy));
	get_random(&operation.dummy2, sizeof(operation.dummy2));
	get_random(&operation.dummy3, sizeof(operation.dummy3));
	get_random(operation.sha1, sizeof(operation.sha1));
			
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	fwrite(&operation, 1, sizeof(operation), out);	
	SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_2, mcu_keys, sizeof(mcu_keys));
	if (ret < 0)
	{
		fprintf(stderr, "Encryption error.\n");
		return ret;
	}
	
	fwrite(mcu_keys, 1, sizeof(mcu_keys), out);
	SHA1Input(ctx, mcu_keys, sizeof(mcu_keys));
	fclose(in);
	return 0;
}

static int write_secondary_security(usb_dev_handle *handle, FILE *in, FILE *out, SHA1Context *ctx)
{
	for (uint32_t offset = 0x10000; offset < 0xC0000; offset += 0x5000)
	{
		CobraUpdateOp operation;
		int ret;
	
		memset(&operation, 0, sizeof(operation));
		operation.opcode = UPDATE_OPCODE_SPI_FLASH;
		operation.data = offset;
		operation.size = 8;
		get_random(operation.dummy, sizeof(operation.dummy));
		get_random(&operation.dummy2, sizeof(operation.dummy2));
		get_random(&operation.dummy3, sizeof(operation.dummy3));
		
		if (fread(g_buf, 1, 8, in) != 8)
		{
			fprintf(stderr, "Secondary security not big enough.\n");
			return -1;
		}
		
		SHA1(g_buf, 8, operation.sha1);	
		
		ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
		if (ret < 0)
		{
			fprintf(stderr, "Encryption error.\n");
			return -1;
		}
		
		fwrite(&operation, 1, sizeof(operation), out);
		SHA1Input(ctx, (uint8_t *)&operation, sizeof(operation));
		fwrite(g_buf, 1, 8, out);
		SHA1Input(ctx, g_buf, 8);
	}
	
	fclose(in);
	return 0;
}

static int attach_sha1(usb_dev_handle *handle, char *firm_path, uint8_t *sha1)
{
	FILE *f = fopen(firm_path, "r+");
	int ret = 0;
	
	if (!f)
	{
		fprintf(stderr, "I/O error.\n");
		ret = -1;
		goto finalize;
	}
	
	ret = cobra_scp_encrypt(handle, COBRA_SCP_DES_KEY_1, sha1, 16);
	
	fseek(f, offsetof(CobraUpdateHeader, sha1), SEEK_SET);
	fwrite(sha1, 1, 20, f);
	
finalize:

	if (f);
		fclose(f);
	
	return ret;
}

char *get_path(char *directory_path, const char *filename)
{
	char path[2048];
	
	snprintf(path, sizeof(path), "%s/%s", directory_path, filename);
	return strdup(path);
}

void create_firmware(char *directory_path, char *firm_path, int mode)
{
	FILE *firm = NULL, *f = NULL;
	usb_dev_handle *handle = NULL;
	CobraUpdateHeader header;
	SHA1Context ctx;
	uint8_t sha1[20];
	int ret = 0;
	char name[32];
		
	SHA1Reset(&ctx);
			
	ret = cobra_open_device(&handle, &serial, 5);
	if (ret != 0)
	{
		fprintf(stderr, "Error opening device.\n");
		goto finalize;
	}
	
	firm = fopen(firm_path, "wb");
	if (!firm)
	{		
		fprintf(stderr, "Error: file %s could not be opened.\n", firm_path);
		goto finalize;
	}	
	
	memset(&header, 0, sizeof(header));
	memcpy(header.id, COBRA_SIG, sizeof(header.id));
	header.format_version = FORMAT_VERSION;
	header.mcu_version = MCU_VERSION;
	header.fw_version = FW_VERSION;
	fwrite(&header, 1, sizeof(header), firm);
	
	memset(name, 0, sizeof(name));
	strcpy(name, FW_NAME);
	fwrite(name, 1, sizeof(name), firm);
	SHA1Input(&ctx, (uint8_t *)name, sizeof(name));
	
	if (mode == 1)
	{
		printf("Writing secondary security...\n");
		
		f = fopen(get_path(directory_path, "security_sec.bin"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open security_sec.\n");
			goto finalize;
		}
		
		if (write_secondary_security(handle, f, firm, &ctx) != 0)
			goto finalize;
	}	
	
	if (mode == 0 || mode == 1)
	{
		printf("Writing security...\n");
		
		f = fopen(get_path(directory_path, "security.bin"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open security.\n");
			goto finalize;
		}
		
		if (write_security(handle, f, firm, &ctx) != 0)
			goto finalize;
	}
	
	if (mode == 1)
	{
		printf("Writing random...\n");		
		
		f = fopen(get_path(directory_path, "random"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open random\n");
			goto finalize;
		}
		
		if (write_file(handle, f, firm, COBRA_TOC_INDEX_RANDOM, &ctx) != 0)
			goto finalize;
		
		printf("Writing ps2softemu stage1.5...\n");
		
		f = fopen(get_path(directory_path, "ps2softemu_stage1_5.xtea"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open ps2softemu stage1.5\n");
			goto finalize;
		}
		
		if (write_file(handle, f, firm, COBRA_TOC_INDEX_PS2SWEMU_STAGE2, &ctx) != 0)
			goto finalize;		
		
		printf("Writing stage1.5...\n");
		
		f = fopen(get_path(directory_path, "stage1_5.rc6"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open stage1.5\n");
			goto finalize;
		}
		
		if (write_file(handle, f, firm, COBRA_TOC_INDEX_STAGE2, &ctx) != 0)
			goto finalize;
		
		printf("Writing ps2hwemu stage1.5...\n");
		
		f = fopen(get_path(directory_path, "ps2hwemu_stage1_5.xtea"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open ps2hwemu stage1.5\n");
			goto finalize;
		}
		
		if (write_file(handle, f, firm, COBRA_TOC_INDEX_PS2HWEMU_STAGE2, &ctx) != 0)
			goto finalize;
		
		printf("Writing ps2gxemu stage1.5...\n");
		
		f = fopen(get_path(directory_path, "ps2gxemu_stage1_5.xtea"), "rb");
		if (!f)
		{
			fprintf(stderr, "Cannot open ps2gxemu stage1.5\n");
			goto finalize;
		}
		
		if (write_file(handle, f, firm, COBRA_TOC_INDEX_PS2GXEMU_STAGE2, &ctx) != 0)
			goto finalize;
		
		printf("Writing TOC...\n");
		if (write_toc(handle, firm, &ctx) != 0)
			goto finalize;
	}	
	
	printf("Writing mcu...\n");
	
	f = fopen(get_path(directory_path, "mcu.bin"), "rb");
	if (!f)
	{
		fprintf(stderr, "Cannot open mcu\n");
		goto finalize;
	}
	
	if (write_mcu(handle, f, firm, &ctx) != 0)
		goto finalize;
	
	fclose(firm);
	firm = NULL;
	f = NULL;
	
	SHA1Result(&ctx, sha1);
	
	if (attach_sha1(handle, firm_path, sha1) != 0)
	{
		goto finalize;
	}
	
	printf("Done.\n");
	
finalize:

	if (firm)
		fclose(firm);
	
	if (f)
		fclose(f);
	
	if (handle)
		cobra_close_device(handle);
}

static void print_usage(char *progname)
{
	printf("Usage: %s <mode> <input directory> <output>\nMode 0 -> clean + security\nMode 1 -> normal firmware\nMode 2 -> only MCU\n", progname);
}

int main(int argc, char *argv[])
{
	int mode;
	
	if (argc != 4)
	{
		print_usage(argv[0]);
		return -1;
	}
	
	if (strlen(argv[1]) != 1 || ((mode = todigit(argv[1][0])) != 0 && mode != 1 && mode != 2))
	{
		printf("Invalid mode specified.\n");
		print_usage(argv[0]);
		return -2;
	}
	
	create_firmware(argv[2], argv[3], mode);
	
	return 0;
}