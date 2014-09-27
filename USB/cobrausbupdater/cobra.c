#include <cell/usbd.h>
#include <cell/sysmodule.h>
#include <sys/timer.h>
#include <sys/memory.h>

 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "cobra.h"
#include "syscall8.h"

#define COBRA_VENDOR_NUM        0xAAAA
#define COBRA_PRODUCT_NUM       0xC0BA

#define RETRY_DELAY	800
#define RESET_DELAY	600

#define REBOOT_TIMEOUT		3000
#define BOOTLOADER_TIMEOUT	7500

#define INITIAL_RESET_DELAY_REBOOT	REBOOT_TIMEOUT
#define INITIAL_RESET_DELAY_BOOTLOADER	BOOTLOADER_TIMEOUT

#define COBRA_VENDOR_NUM        0xAAAA
#define COBRA_PRODUCT_NUM       0xC0BA

#define TYPE_HOST2DEV (USB_REQTYPE_DIR_TO_DEVICE|USB_REQTYPE_TYPE_VENDOR)
#define TYPE_DEV2HOST (USB_REQTYPE_DIR_TO_HOST|USB_REQTYPE_TYPE_VENDOR)

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

static void sleep_mili(uint32_t milisecs)
{
	sys_timer_usleep(milisecs*1000);
}

static inline int cobra_usb_command(uint8_t command, int requestType, uint32_t addr, void *buf, uint16_t size)
{
	system_call_6(8, SYSCALL8_OPCODE_COBRA_USB_COMMAND, command, requestType, addr, (uint64_t)(uint32_t)buf, size);
	return (int)p1;
}

static int wait_reset(uint32_t initial_delay, uint32_t timeout)
{
	sleep_mili(initial_delay);
	return 0;
}

int cobra_open_device(void)
{
	return cobra_usb_command(CMD_LED_CONTROL, TYPE_HOST2DEV, COBRA_LED_BLUE, NULL, 0);
}

int cobra_close_device(void)
{
	return 0;
}

int cobra_spi_flash_read(uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(CMD_SPI_FLASH_READ, TYPE_DEV2HOST, addr ,buf, size);
}

int cobra_spi_flash_page_program(uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(CMD_SPI_FLASH_PAGE_PROGRAM, TYPE_HOST2DEV, addr, buf, size);
}

int cobra_spi_flash_decrypt_and_page_program(uint32_t addr, void *buf, uint16_t size)
{
	if (size & 7)
		return -1;
	
	return cobra_usb_command(CMD_SPI_FLASH_DECRYPT_AND_PAGE_PROGRAM, TYPE_HOST2DEV, addr, buf, size);
}

int cobra_spi_flash_erase_sector(uint32_t addr)
{
	return cobra_usb_command(CMD_SPI_FLASH_ERASE_SECTOR, TYPE_HOST2DEV, addr, NULL, 0);
}

int cobra_spi_flash_chip_erase(void)
{
	return cobra_usb_command(CMD_SPI_FLASH_CHIP_ERASE, TYPE_HOST2DEV, 0, NULL, 0);
}

int cobra_spi_flash_hash(uint32_t addr, uint32_t size, uint8_t *sha1)
{
	int ret = cobra_usb_command(CMD_SPI_FLASH_SET_HASH_SIZE, TYPE_HOST2DEV, size, NULL, 0);
	if (ret < 0)
		return ret;
	
	return cobra_usb_command(CMD_SPI_FLASH_HASH, TYPE_DEV2HOST, addr, sha1, 20);
}

int cobra_scp_flashrom_read(uint8_t addr, void *buf, uint8_t size)
{
	return cobra_usb_command(CMD_SCP_FLASHROM_READ, TYPE_DEV2HOST, addr, buf, size);
}

int cobra_scp_decrypt(uint8_t key, void *buf, uint32_t size)
{
	uint8_t *buf8 = buf;
	
	if (size & 7)
		return -1;
	
	for (uint32_t i = 0; i < size; i += 8, buf8 += 8)
	{
		int ret = cobra_usb_command(CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, 0, buf8, 8);
		if (ret < 0)
			return ret;
		
		ret = cobra_usb_command(CMD_SCP_CRYPT, TYPE_DEV2HOST, 0x0100 | key, buf8, 8);
		if (ret < 0)
			return ret;
	}
	
	return 0;
}

int cobra_mcu_eeprom_decrypt_and_write(uint16_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(CMD_MCU_EEPROM_DECRYPT_AND_WRITE, TYPE_HOST2DEV, addr, buf, size);
}

int cobra_mcu_reboot(void)
{
	int ret = cobra_usb_command(CMD_MCU_REBOOT, TYPE_HOST2DEV, 0, NULL, 0);
	if (ret < 0 && ret != -34)
	{
		DPRINTF("Reboot error %x\n", ret);		
	}
	
	return wait_reset(INITIAL_RESET_DELAY_REBOOT, REBOOT_TIMEOUT);
}

int cobra_mcu_start_bootloader(uint32_t data, uint8_t *key)
{
	int ret;
	
	ret = cobra_mcu_eeprom_decrypt_and_write(0x4, key, 16);
	if (ret < 0)
		return ret;		
		
	ret = cobra_usb_command(CMD_MCU_START_BOOTLOADER, TYPE_HOST2DEV, data, NULL, 0);
	if (ret < 0 && ret != -34 && ret != -5)
	{
		DPRINTF("Initial start bootloader error %x\n", ret);
	}
	
	return wait_reset(INITIAL_RESET_DELAY_BOOTLOADER, BOOTLOADER_TIMEOUT);
}
