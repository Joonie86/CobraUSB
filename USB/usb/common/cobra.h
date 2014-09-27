#ifndef __COBRA_H__
#define __COBRA_H__

#include <usb.h>
#include <stdint.h>

#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

#define COBRA_MCU_FLASH_SIZE			16384
#define COBRA_MCU_PAGE_SIZE			128
#define COBRA_MCU_TOTAL_PAGES			(COBRA_MCU_FLASH_SIZE/COBRA_MCU_PAGE_SIZE)
#define COBRA_MCU_USER_PROGRAM_SIZE		15872	
#define COBRA_MCU_USER_PROGRAM_SIZE2		12288
#define COBRA_MCU_BOOTLOADER_SIZE		512

#define COBRA_SPI_FLASH_PAGE_SIZE		256
#define COBRA_SPI_FLASH_SECTOR_SIZE		4096
#define COBRA_SPI_FLASH_SIZE			(2*1024*1024)

#define COBRA_SPI_FLASH_TOTAL_PAGES		(COBRA_SPI_FLASH_SIZE/COBRA_SPI_PAGE_SIZE)
#define COBRA_SPI_FLASH_TOTAL_SECTORS		(COBRA_SPI_FLASH_SIZE/COBRA_TOTAL_SECTORS)
#define COBRA_SPI_FLASH_PAGES_PER_SECTOR	(COBRA_SPI_SECTOR_SIZE/COBRA_SPI_PAGE_SIZE)

#define COBRA_SCP_FLASHROM_SIZE			32

#define COBRA_TOC_SPI_FLASH_ADDRESS		0x100000

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
	COBRA_TOC_INDEX_RANDOM,
	COBRA_TOC_NUM_ITEMS
};

int cobra_open_device(usb_dev_handle **handle, uint64_t *serial, uint32_t nretries);
int cobra_close_device(usb_dev_handle *handle);
int cobra_spi_flash_read(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_page_program(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_decrypt_and_page_program(usb_dev_handle *handle, uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_erase_sector(usb_dev_handle *handle, uint32_t addr);
int cobra_spi_flash_chip_erase(usb_dev_handle *handle);
int cobra_spi_flash_hash(usb_dev_handle *handle, uint32_t addr, uint32_t size, uint8_t *sha1);
int cobra_scp_flashrom_read(usb_dev_handle *handle, uint8_t addr, void *buf, uint8_t size);
int cobra_scp_decrypt(usb_dev_handle *handle, uint8_t key, void *buf, uint32_t size);
int cobra_scp_encrypt(usb_dev_handle *handle, uint8_t key, void *buf, uint32_t size);
int cobra_scp_handshake(usb_dev_handle *handle, uint8_t key, uint8_t dynamic, void *buf, uint32_t size);
int cobra_scp_set_user_key(usb_dev_handle *handle, uint8_t *key);
int cobra_scp_set_jtag(usb_dev_handle *handle, uint8_t jtag);
int cobra_scp_read_tdo(usb_dev_handle *handle, uint8_t *tdo);
int cobra_mcu_eeprom_decrypt_and_write(usb_dev_handle *handle, uint16_t addr, void *buf, uint16_t size);
int cobra_mcu_reboot(usb_dev_handle **handle);
int cobra_mcu_start_bootloader(usb_dev_handle **handle, uint32_t data, uint8_t *key);

#endif


