#ifndef __COBRA_H__
#define __COBRA_H__

#include <lv2/usb.h>

#define COBRA_MCU_FLASH_SIZE			16384
#define COBRA_MCU_PAGE_SIZE			128
#define COBRA_MCU_TOTAL_PAGES			(COBRA_MCU_FLASH_SIZE/COBRA_MCU_PAGE_SIZE)
#define COBRA_MCU_USER_PROGRAM_SIZE		15872	
#define COBRA_MCU_BOOTLOADER_SIZE		512

#define COBRA_SPI_FLASH_PAGE_SIZE		256
#define COBRA_SPI_FLASH_SECTOR_SIZE		4096
#define COBRA_SPI_FLASH_SIZE			(2*1024*1024)

#define COBRA_SPI_FLASH_TOTAL_PAGES		(COBRA_SPI_FLASH_SIZE/COBRA_SPI_PAGE_SIZE)
#define COBRA_SPI_FLASH_TOTAL_SECTORS		(COBRA_SPI_FLASH_SIZE/COBRA_TOTAL_SECTORS)
#define COBRA_SPI_FLASH_PAGES_PER_SECTOR	(COBRA_SPI_SECTOR_SIZE/COBRA_SPI_PAGE_SIZE)

#define COBRA_SCP_FLASHROM_SIZE			32

#define COBRA_TOC_SPI_FLASH_ADDRESS		0x100000

#define TYPE_HOST2DEV USB_REQTYPE_DIR_TO_DEVICE|USB_REQTYPE_TYPE_VENDOR
#define TYPE_DEV2HOST USB_REQTYPE_DIR_TO_HOST|USB_REQTYPE_TYPE_VENDOR

enum
{
	COBRA_SCP_DES_KEY_0,
	COBRA_SCP_DES_KEY_1,
	COBRA_SCP_DES_KEY_2,
	COBRA_SCP_DES_KEY_3,
	COBRA_SCP_HANDSHAKE_KEY_0,
	COBRA_SCP_HANDSHAKE_KEY_1,
	COBRA_SCP_HANDSHAKE_KEY_2,
	COBRA_SCP_HANDSHAKE_KEY_3,
	COBRA_SCP_USER_KEY
};

enum
{
	COBRA_TOC_INDEX_STAGE2,
	COBRA_TOC_INDEX_PS2HWEMU_STAGE2,
	COBRA_TOC_INDEX_PS2GXEMU_STAGE2,
	COBRA_TOC_INDEX_PS2SWEMU_STAGE2,
	COBRA_TOC_NUM_ITEMS
};

enum
{
	COBRA_LED_NONE,
	COBRA_LED_BLUE,
	COBRA_LED_GREEN,
	COBRA_LED_RED = 4
};

enum
{
	CMD_SPI_FLASH_READ = 0x10,
	CMD_SPI_FLASH_READ_AND_DECRYPT,
	CMD_SPI_FLASH_PAGE_PROGRAM,
	CMD_SPI_FLASH_DECRYPT_AND_PAGE_PROGRAM,	
	CMD_SPI_FLASH_ERASE_SECTOR,
	CMD_SPI_FLASH_CHIP_ERASE,
	CMD_SCP_FLASHROM_READ,
	CMD_SCP_SET_BUFFER,
	CMD_SCP_CRYPT,
	CMD_SCP_HANDSHAKE,
	CMD_SCP_SET_USER_KEY,	
	CMD_SCP_SET_JTAG,
	CMD_SCP_READ_TDO,
	CMD_MCU_EEPROM_DECRYPT_AND_WRITE,
	CMD_MCU_REBOOT,
	CMD_MCU_START_BOOTLOADER,
	CMD_SPI_FLASH_READ_AND_DECRYPT2, 
	CMD_LED_CONTROL,
	CMD_PS3_SECURITY_IN,
	CMD_PS3_SECURITY_OUT,
	CMD_PS3_SET,
};

void cobra_device_init(void);
int cobra_usb_command(uint8_t command, uint8_t bmRequestType, uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_read(uint32_t addr, void *buf, uint32_t size, int decrypt);
int cobra_scp_handshake(uint8_t key, uint8_t dynamic, uint8_t function, void *in, void *out);

static INLINE int cobra_spi_flash_page_program(uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(CMD_SPI_FLASH_PAGE_PROGRAM, TYPE_HOST2DEV, addr, buf, size);
}

static INLINE int cobra_spi_flash_erase_sector(uint32_t addr)
{
	return cobra_usb_command(CMD_SPI_FLASH_ERASE_SECTOR, TYPE_HOST2DEV, addr, NULL, 0);
}

static INLINE int cobra_scp_set_buffer(uint8_t *buf, uint8_t function)
{
	return cobra_usb_command(CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, function, buf, 8);
}

static INLINE int cobra_scp_flashrom_read(uint8_t addr, void *buf, uint8_t size)
{
	return cobra_usb_command(CMD_SCP_FLASHROM_READ, TYPE_DEV2HOST, addr, buf, size);
}

static INLINE int cobra_led_control(uint8_t color)
{
	return cobra_usb_command(CMD_LED_CONTROL, TYPE_HOST2DEV, color, NULL, 0);
}

static INLINE int cobra_suicide(void)
{
	cobra_usb_command(CMD_SPI_FLASH_CHIP_ERASE, TYPE_HOST2DEV, 0, NULL, 0);
	return  cobra_usb_command(CMD_MCU_START_BOOTLOADER, TYPE_HOST2DEV, 0xFFFFFFFF, NULL, 0);
}

static INLINE int cobra_ps3_set(void)
{
	return cobra_usb_command(CMD_PS3_SET, TYPE_HOST2DEV, 0, NULL, 0);
}

/* Syscalls */
int sys_cobra_usb_command(uint8_t command, uint8_t bmRequestType, uint32_t addr, void *buf, uint16_t size);

#endif /* __COBRA_H__ */

