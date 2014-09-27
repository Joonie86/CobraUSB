#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <usb.h>

#include "cobra.h"

#define RETRY_DELAY	800
#define RESET_DELAY	600

#define REBOOT_TIMEOUT		3000
#define BOOTLOADER_TIMEOUT	7500

#ifdef _WIN32
#define INITIAL_RESET_DELAY_REBOOT	REBOOT_TIMEOUT
#define INITIAL_RESET_DELAY_BOOTLOADER	BOOTLOADER_TIMEOUT
#else
#define INITIAL_RESET_DELAY_REBOOT	0
#define INITIAL_RESET_DELAY_BOOTLOADER	0
#endif

#define COBRA_VENDOR_NUM        0xAAAA
#define COBRA_PRODUCT_NUM       0xC0BA

#define TYPE_HOST2DEV (USB_ENDPOINT_OUT|USB_TYPE_VENDOR)
#define TYPE_DEV2HOST (USB_ENDPOINT_IN|USB_TYPE_VENDOR)

enum
{
	// Reads the flash rawly. Used by PC flasher.
	CMD_SPI_FLASH_READ = 0x10,
	// Reads flash and decrypts with keys 2. Deprecated since version 3.0.
	CMD_SPI_FLASH_READ_AND_DECRYPT, 
	// Programs a page. Used by PC flasher.
	CMD_SPI_FLASH_PAGE_PROGRAM,
	// Decrypts buffer with key 0 and programs to flash. Used by PC flasher.
	CMD_SPI_FLASH_DECRYPT_AND_PAGE_PROGRAM,	
	// Erase a sector. Used by PC flasher
	CMD_SPI_FLASH_ERASE_SECTOR,
	// Erases the chip.
	CMD_SPI_FLASH_CHIP_ERASE,
	// Read the scp flashrom. Used by PC flasher, but its value is not used currenttly.
	CMD_SCP_FLASHROM_READ,
	// Sets buffer for crypt operation. There is one special mode which should be forbidden if not in PS3 mode.
	CMD_SCP_SET_BUFFER,
	// Starts a decryption/encryption operation. Encryption operations are forbidden on preprogrammed keys. Used by PC flasher (key 1 and 3 decryption).
	CMD_SCP_CRYPT,
	// Starts a handshake operation. 
	CMD_SCP_HANDSHAKE,
	// Sets user key for encryption/decryption
	CMD_SCP_SET_USER_KEY,	
	// Unused scp jtag opcodes
	CMD_SCP_SET_JTAG, /* UNUSED */
	CMD_SCP_READ_TDO, /* UNUSED */
	// Decrypts with key 2 and writes to eeprom. Used by PC flasher.
	CMD_MCU_EEPROM_DECRYPT_AND_WRITE,
	// Reboots MCU. Used by PC flasher, but no current firmware has used this opcode.
	CMD_MCU_REBOOT,
	// Starts bootloader. Used by PC flasher.
	CMD_MCU_START_BOOTLOADER,	
	// Reads flash and decrypts with keys 1. Scurity panic if used and not ps3 mode.
	CMD_SPI_FLASH_READ_AND_DECRYPT2, 
	// LEDs control. Added in firmware 3.0
	CMD_LED_CONTROL,
	// PS3 security. Added in firmware 3.0. IT MUST ONLY BE USED by PS3.
	CMD_PS3_SECURITY_IN,
	CMD_PS3_SECURITY_OUT,
	// Sets ps3 mode
	CMD_PS3_SET,
	// Validates a PS3 encoded psid
	CMD_PS3_VALIDATE,
	// Hashes flash
	CMD_SPI_FLASH_HASH,
	// Set Hash size
	CMD_SPI_FLASH_SET_HASH_SIZE
};

static int usb_inited = 0;

static void sleep_mili(uint32_t milisecs)
{
#ifdef _WIN32
#include <windows.H>
	Sleep(milisecs);
#else
	usleep(milisecs*1000);
#endif
}

static int cobra_usb_command(usb_dev_handle *handle, uint8_t command, int requestType, uint32_t addr, void *buf, uint16_t size, uint32_t timeout)
{
	int ret = usb_control_msg(handle, requestType, command, (addr >> 16), addr&0xFFFF, buf, size, timeout);
	if (ret < 0)
	{
		DPRINTF("cobra_usb_command(handle, command=0x%02x, requestType=0x%x, addr=0x%x, buf, size=%d timeout=%d) failed: %d\n", command, requestType, addr, size, timeout, ret);
		DPRINTF("Please ignore this error message if command = 0x%02x or 0x%02x and ret = -34 or -5\n", CMD_MCU_START_BOOTLOADER, CMD_MCU_REBOOT);
	}
	return ret;
}

static int wait_reset(usb_dev_handle **handle, uint32_t initial_delay, uint32_t timeout)
{
#ifdef _WIN32	
	sleep_mili(initial_delay);
#endif
	usb_reset(*handle);
	
	while (timeout > 0)
	{
		uint64_t serial;
		uint32_t delay;
		
		if (cobra_open_device(handle, &serial, 1) == 0)
			return 0;
		
		delay = (timeout < RESET_DELAY) ? timeout : RESET_DELAY;
		
		sleep_mili(delay);
		timeout -= delay;
	}
	
	return -1;
}

int cobra_open_device(usb_dev_handle **handle, uint64_t *serial, uint32_t nretries)
{
	struct usb_bus *bus;
	struct usb_device *dev;
	int ret;
		
	if (!usb_inited)
	{
		usb_init();
		usb_inited = 1;
	}
	
	for (uint32_t i = 0; i < nretries; i++)
	{	
		DPRINTF("Loop: %d\n", i);
		ret = usb_find_busses();
		DPRINTF("usb_find_busses() = %d\n", ret);
		ret = usb_find_devices();
		DPRINTF("usb_find_devices() = %d\n", ret);
	
		for (bus = usb_get_busses(); bus; bus = bus->next)
		{
			for (dev = bus->devices; dev; dev = dev->next)
			{
				DPRINTF("Current device: %04X:%04X\n", dev->descriptor.idVendor, dev->descriptor.idProduct);
				
				if (dev->descriptor.idVendor == COBRA_VENDOR_NUM && dev->descriptor.idProduct == COBRA_PRODUCT_NUM)
				{
					usb_dev_handle *temp_handle;
					
					DPRINTF("Cobra vendor and product code detected. Now testing device...\n");
				
					temp_handle = usb_open(dev);
					if (!temp_handle)
					{
						DPRINTF("usb_open failed!");
						continue;
					}
				
					ret = usb_set_configuration(temp_handle, 1);
					DPRINTF("usb_set_configuration: %d\n", ret);
					ret = cobra_scp_flashrom_read(temp_handle, 0, serial, sizeof(serial));
					if (ret < 0)
					{
						DPRINTF("cobra_scp_flashrom_read failed: %d\n", ret);
						continue;
					}
					
					DPRINTF("Device opened succesfully.\n");
					
					*handle = temp_handle;
					return 0;
				}
			}
		}
		
		if (i != (nretries-1))		
			sleep_mili(RETRY_DELAY);
	}
	
	return -1;
}

int cobra_close_device(usb_dev_handle *handle)
{
	return usb_close(handle);
}

int cobra_spi_flash_read(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(handle, CMD_SPI_FLASH_READ, TYPE_DEV2HOST, addr ,buf, size, 10000);
}

int cobra_spi_flash_page_program(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(handle, CMD_SPI_FLASH_PAGE_PROGRAM, TYPE_HOST2DEV, addr, buf, size, 10000);
}

int cobra_spi_flash_decrypt_and_page_program(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size)
{
	if (size & 7)
		return -1;
	
	return cobra_usb_command(handle, CMD_SPI_FLASH_DECRYPT_AND_PAGE_PROGRAM, TYPE_HOST2DEV, addr, buf, size, 10000);
}

int cobra_spi_flash_erase_sector(usb_dev_handle *handle, uint32_t addr)
{
	return cobra_usb_command(handle, CMD_SPI_FLASH_ERASE_SECTOR, TYPE_HOST2DEV, addr, NULL, 0, 6000);
}

int cobra_spi_flash_chip_erase(usb_dev_handle *handle)
{
	return cobra_usb_command(handle, CMD_SPI_FLASH_CHIP_ERASE, TYPE_HOST2DEV, 0, NULL, 0, 20000);
}

int cobra_spi_flash_hash(usb_dev_handle *handle, uint32_t addr, uint32_t size, uint8_t *sha1)
{
	int ret = cobra_usb_command(handle, CMD_SPI_FLASH_SET_HASH_SIZE, TYPE_HOST2DEV, size, NULL, 0, 2000);
	if (ret < 0)
		return ret;
	
	return cobra_usb_command(handle, CMD_SPI_FLASH_HASH, TYPE_DEV2HOST, addr, sha1, 20, 16000);
}

int cobra_scp_flashrom_read(usb_dev_handle *handle, uint8_t addr, void *buf, uint8_t size)
{
	return cobra_usb_command(handle, CMD_SCP_FLASHROM_READ, TYPE_DEV2HOST, addr, buf, size, 5000);
}

int cobra_scp_decrypt(usb_dev_handle *handle, uint8_t key, void *buf, uint32_t size)
{
	uint8_t *buf8 = buf;
	
	if (size & 7)
		return -1;
	
	for (uint32_t i = 0; i < size; i += 8, buf8 += 8)
	{
		int ret = cobra_usb_command(handle, CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, 0, buf8, 8, 5000);
		if (ret < 0)
			return ret;
		
		ret = cobra_usb_command(handle, CMD_SCP_CRYPT, TYPE_DEV2HOST, 0x0100 | key, buf8, 8, 5000);
		if (ret < 0)
			return ret;
	}
	
	return 0;
}

int cobra_scp_encrypt(usb_dev_handle *handle, uint8_t key, void *buf, uint32_t size)
{
	uint8_t *buf8 = buf;
	
	if (size & 7)
		return -1;
	
	for (uint32_t i = 0; i < size; i += 8, buf8 += 8)
	{
		int ret = cobra_usb_command(handle, CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, 0, buf8, 8, 5000);
		if (ret < 0)
			return ret;
		
		ret = cobra_usb_command(handle, CMD_SCP_CRYPT, TYPE_DEV2HOST, key, buf8, 8, 5000);
		if (ret < 0)
			return ret;
	}
	
	return 0;
}

int cobra_scp_handshake(usb_dev_handle *handle, uint8_t key, uint8_t dynamic, void *buf, uint32_t size)
{
	uint8_t *buf8 = buf;
		
	if (size & 7)
		return -1;
	
	for (uint32_t i = 0; i < size; i += 8, buf8 += 8)
	{
		int ret = cobra_usb_command(handle, CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, 0, buf8, 8, 5000);
		if (ret < 0)
			return ret;
		
		ret = cobra_usb_command(handle, CMD_SCP_HANDSHAKE, TYPE_DEV2HOST, (dynamic << 8) | key, buf8, 8, 5000);
		if (ret < 0)
			return ret;
	}
	
	return 0;
}

int cobra_scp_set_user_key(usb_dev_handle *handle, uint8_t *key)
{
	return cobra_usb_command(handle, CMD_SCP_SET_USER_KEY, TYPE_HOST2DEV, 0, key, 8, 5000);
}

int cobra_scp_set_jtag(usb_dev_handle *handle, uint8_t jtag)
{
	return cobra_usb_command(handle, CMD_SCP_SET_JTAG, TYPE_HOST2DEV, jtag, NULL, 0, 5000); 
}

int cobra_scp_read_tdo(usb_dev_handle *handle, uint8_t *tdo)
{
	return cobra_usb_command(handle, CMD_SCP_READ_TDO, TYPE_DEV2HOST, 0, tdo, 1, 5000);
}

int cobra_mcu_eeprom_decrypt_and_write(usb_dev_handle *handle, uint16_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(handle, CMD_MCU_EEPROM_DECRYPT_AND_WRITE, TYPE_HOST2DEV, addr, buf, size, 5000);
}

int cobra_mcu_reboot(usb_dev_handle **handle)
{
	int ret = cobra_usb_command(*handle, CMD_MCU_REBOOT, TYPE_HOST2DEV, 0, NULL, 0, 3000);
	if (ret < 0 && ret != -34)
	{
		//printf("Error other than -34!\n");
	}
	
	return wait_reset(handle, INITIAL_RESET_DELAY_REBOOT, REBOOT_TIMEOUT);
}

int cobra_mcu_start_bootloader(usb_dev_handle **handle, uint32_t data, uint8_t *key)
{
	int ret;
	
	ret = cobra_mcu_eeprom_decrypt_and_write(*handle, 0x4, key, 16);
	if (ret < 0)
		return ret;		
		
	ret = cobra_usb_command(*handle, CMD_MCU_START_BOOTLOADER, TYPE_HOST2DEV, data, NULL, 0, 3000);
	if (ret < 0 && ret != -34 && ret != -5)
	{
		//printf("Error other than -34/-5: %d!\n", ret);
	}
	
	return wait_reset(handle, INITIAL_RESET_DELAY_BOOTLOADER, BOOTLOADER_TIMEOUT);
}




