#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#include "cobra.h"
#include "cobraupdate.h"
#include "sha1.h"

#define MAX_SIZE		1048576
#define WRITE_RETRIES		10

//#define DPRINTF	printf

uint8_t g_buf[MAX_SIZE];
uint64_t serial;

static void SHA1(void *buf, uint16_t size, uint8_t *sha1)
{
	SHA1Context ctx;
	
	SHA1Reset(&ctx);
	SHA1Input(&ctx, buf, size);
	SHA1Result(&ctx, sha1);
}

static int is_empty_page(uint8_t *buf)
{
	for (int i = 0; i < COBRA_SPI_FLASH_PAGE_SIZE; i++)
		if (buf[i] != 0xFF)
			return 0;
		
	return 1;
}

static int _spi_flash_write(usb_dev_handle *handle, uint32_t address, uint8_t*buf, uint32_t size, int decrypt)
{
	static uint8_t sector_buf[COBRA_SPI_FLASH_SECTOR_SIZE];
	uint32_t sector_address;
	uint32_t remaining;
	int ret;
	
	if (size == 0)
		return 0;
	
	if ((address+size) > COBRA_SPI_FLASH_SIZE)
		return -1;
	
	sector_address = address;
	remaining = size;
	
	while (remaining > 0)
	{
		uint32_t write_size;
		
		write_size = COBRA_SPI_FLASH_SECTOR_SIZE;
		if (write_size > remaining)
			write_size = remaining;
		
		memset(sector_buf, 0xff, sizeof(sector_buf));
		memcpy(sector_buf, buf, write_size);
			
		ret = cobra_spi_flash_erase_sector(handle, sector_address);
		if (ret < 0)
			return ret;
			
		for (uint32_t i = 0; i < COBRA_SPI_FLASH_SECTOR_SIZE; i += COBRA_SPI_FLASH_PAGE_SIZE)
		{
			if (decrypt || !is_empty_page(sector_buf+i))
			{
				//DPRINTF("Write page %x  (%d)\n", sector_address+i, decrypt);
			  
				if (decrypt)
					ret = cobra_spi_flash_decrypt_and_page_program(handle, sector_address+i, sector_buf+i, COBRA_SPI_FLASH_PAGE_SIZE);
				else
					ret = cobra_spi_flash_page_program(handle, sector_address+i, sector_buf+i, COBRA_SPI_FLASH_PAGE_SIZE);
					
				if (ret < 0)
					return ret;
			}
		}
		
		sector_address += COBRA_SPI_FLASH_SECTOR_SIZE;
		address += write_size;
		remaining -= write_size;
		buf += write_size;
	}
	
	return 0;
}

static int verify_write_old(usb_dev_handle *handle, uint32_t address, uint32_t size, uint8_t *sha1)
{
	int ret; 
	uint8_t read_sha1[20];
	uint8_t *buf = malloc(size);
	uint8_t *ptr = buf;
	uint32_t remaining = size;
	uint32_t current_address = address;
		
	while (remaining > 0)
	{	
		uint32_t block_size;
		
		if (remaining > 4096)
			block_size = 4096;
		else
			block_size = remaining;
		
		ret = cobra_spi_flash_read(handle, current_address, ptr, block_size);
		if (ret < 0)
		{
			free(buf);
			return ret;
		}
		
		remaining -= block_size;
		ptr += block_size;
		current_address += block_size;
	}
	
	SHA1(buf, size, read_sha1);	
	free(buf);
	
	return (memcmp(sha1, read_sha1, 20) == 0);
}

static int spi_flash_write(usb_dev_handle *handle, uint32_t address, uint8_t*buf, uint32_t size, int decrypt, uint8_t *sha1)
{	
	int ret;
	static int new_method = 1;
	uint8_t read_sha1[20];
	
	if (new_method)
	{
		/*memset(read_sha1, 0x55, 20);
		
		ret = cobra_spi_flash_hash(handle, address, size, read_sha1);
		if (ret < 0)
			new_method = 0;	
		else
		{
			int i;
			
			for (i = 0; i < 16; i++)
			{
				if (read_sha1[i] != 0x55)
					break;
			}
			
			if (i == 16)
				new_method = 0;
		}
		
		if (!new_method)
		{
			DPRINTF("Using old method.\n");
		}*/
		new_method = 0;
	}
	
	if (memcmp(read_sha1, sha1, 20) == 0)
	{
		DPRINTF("%x %x doesn't need update.\n", address, size);
		return 0;
	}
		
	for (int i = 0; i < WRITE_RETRIES; i++)
	{
		ret = _spi_flash_write(handle, address, buf, size, decrypt);
		if (ret < 0)
			return ret;
		
		if (new_method)
		{
			ret = cobra_spi_flash_hash(handle, address, size, read_sha1);
			if (ret < 0)
				return ret;
			
			if (memcmp(read_sha1, sha1, 20) == 0)
				break;			
		}
		else
		{		
			ret = verify_write_old(handle, address, size, sha1);
			if (ret != 0)
			{
				if (ret == 1)
					ret = 0;
			
				break;
			}			
		}
		
		DPRINTF("verifify_write failed on try #%d\n", i+1);
		if (i == (WRITE_RETRIES-1))
		{
			printf("All write retries to %x failed. Please contact Cobra USB Team.\n", address);
			exit(-1);
		}
	}
	
	return ret;
}

int verify_file(usb_dev_handle *handle, FILE *f, CobraUpdateHeader *header)
{
	SHA1Context ctx;
	int ret;
	uint32_t pos = ftell(f);
	uint32_t read;
	uint8_t sha1[20];
	
	if (memcmp(header->id, COBRA_SIG, sizeof(header->id)) != 0)
		return -1;
	
	ret = cobra_scp_decrypt(handle, COBRA_SCP_DES_KEY_1, header->sha1, 16);
	if (ret < 0)
	{
		DPRINTF("Verify 1 failed.\n");
		return -1;
	}
	
	SHA1Reset(&ctx);
	
	while ((read = fread(g_buf, 1, MAX_SIZE, f)) > 0)
	{
		SHA1Input(&ctx, g_buf, read);
	}
	
	SHA1Result(&ctx, sha1);
	if (memcmp(sha1, header->sha1, 16) != 0)
		return -1;
	
	fseek(f, pos, SEEK_SET);
	return 0;
}

int update(char *file)
{
	FILE *f = NULL;
	usb_dev_handle *handle = NULL;
	CobraUpdateHeader header;
	CobraUpdateOp operation;
	int ret = 0;
	char name[32];
	
	f = fopen(file, "rb");
	if (!f)
	{
		ret = ERROR_FILE_OPEN;
		goto finalize;
	}
	
	ret = cobra_open_device(&handle, &serial, 8);
	if (ret != 0)
	{
		ret = ERROR_DEVICE_OPEN;
		goto finalize;
	}	
	
	//printf("Verifying file...\n");
	
	if (fread(&header, 1, sizeof(header), f) != sizeof(header) || verify_file(handle, f, &header) != 0)
	{
		ret = ERROR_INVALID_FILE;
		goto finalize;
	}
	
	if (header.format_version > FORMAT_VERSION)
	{
		ret = ERROR_NEED_HIGHER_VERSION;
		goto finalize;
	}
	else if (header.format_version < FORMAT_VERSION)
	{
		ret = ERROR_OLD_NOT_SUPPORTED;
		goto finalize;
	}
	
	if (fread(name, 1, sizeof(name), f) != sizeof(name))
	{
		ret = ERROR_INVALID_FILE;
		goto finalize;
	}
	
	name[31] = 0;
	printf("Programming %s...\n", name);
	
	while (fread(&operation, 1, sizeof(operation), f) == sizeof(operation))
	{
		ret = cobra_scp_decrypt(handle, COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
		if (ret < 0)
		{
			ret = ERROR_COMUNICATION_ERROR;
			goto finalize;
		}		
		
		if (operation.size > MAX_SIZE)
		{
			ret = ERROR_INVALID_FILE;
			goto finalize;
		}
		
		if (operation.size > 0 && fread(g_buf, 1, operation.size, f) != operation.size)
		{
			ret = ERROR_INVALID_FILE;
			goto finalize;
		}		
		
		switch (operation.opcode)
		{
			case UPDATE_OPCODE_SPI_FLASH:
				ret = spi_flash_write(handle, operation.data, g_buf, operation.size, 0, operation.sha1);			
			break;
			
			case UPDATE_OPCODE_SPI_FLASH_DEC:
				ret = spi_flash_write(handle, operation.data, g_buf, operation.size, 1, operation.sha1);	
			break;
			
			case UPDATE_OPCODE_START_BOOTLOADER:
			{
				ret = cobra_mcu_start_bootloader(&handle, operation.data, g_buf);
				//printf("bootloader ret = %X\n", ret);				
			}
			break;
			
			case UPDATE_OPCODE_REBOOT:
				ret = cobra_mcu_reboot(&handle);
			break;
		}
		
		if (ret < 0)
		{
			ret = ERROR_COMUNICATION_ERROR;
			goto finalize;
		}
	}
	
finalize:

	switch (ret)
	{
		case 0:
			printf("\nDone.");
		break;
		
		case ERROR_FILE_OPEN:
			fprintf(stderr, "\nError opening file.\n");
		break;
		
		case ERROR_DEVICE_OPEN:
			fprintf(stderr, "\nError opening device: COBRA was not found.\n");
		break;
		
		case ERROR_INVALID_FILE:
			fprintf(stderr, "\nInvalid update file.\n");
		break;
		
		case ERROR_NEED_HIGHER_VERSION:
			fprintf(stderr, "\nThis update requires a higher version of the flasher.\n");
		break;
		
		case ERROR_COMUNICATION_ERROR:
			fprintf(stderr, "\nCommunication error with device (device unplugged?)\n");
		break;
		
		case ERROR_OLD_NOT_SUPPORTED:
			fprintf(stderr, "\nOld firmware format is not supported by this version of the flasher.\n");
		break;
	}

	if (f)
		fclose(f);
	
	if (handle)
		cobra_close_device(handle);
	
	return ret;
}

static void wait_enter(void)
{
	while (getchar() != '\n');
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s <update file>\n\nPress ENTER to quit.", argv[0]);
		wait_enter();
		return -1;
	}
	
	time_t seconds = time(NULL);
	
	int ret = update(argv[1]);
	//printf("%d\n", ret);
		
	seconds = time(NULL) - seconds;
	DPRINTF("Elapsed %ld seconds.\n", seconds);
	
	printf("\nPress ENTER to quit.");
	wait_enter();	
	return ret;
}