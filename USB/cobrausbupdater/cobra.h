#ifndef __COBRA_H__
#define __COBRA_H__

#ifdef __cplusplus
extern "C" {
#endif

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

int cobra_open_device(void);
int cobra_close_device(void);
int cobra_spi_flash_read(uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_page_program(uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_decrypt_and_page_program(uint32_t addr, void *buf, uint16_t size);
int cobra_spi_flash_erase_sector(uint32_t addr);
int cobra_spi_flash_chip_erase(void);
int cobra_spi_flash_hash(uint32_t addr, uint32_t size, uint8_t *sha1);
int cobra_scp_flashrom_read(uint8_t addr, void *buf, uint8_t size);
int cobra_scp_decrypt(uint8_t key, void *buf, uint32_t size);
int cobra_mcu_eeprom_decrypt_and_write(uint16_t addr, void *buf, uint16_t size);
int cobra_mcu_reboot(void);
int cobra_mcu_start_bootloader(uint32_t data, uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif /* __COBRA_H__ */

