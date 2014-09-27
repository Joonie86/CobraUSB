#ifndef __COBRAUPDATE_H__

#define COBRA_SIG		"COBRA\0"
#define FORMAT_VERSION		1

enum 
{
	UPDATE_OPCODE_SPI_FLASH,
	UPDATE_OPCODE_SPI_FLASH_DEC,
	UPDATE_OPCODE_START_BOOTLOADER,
	UPDATE_OPCODE_REBOOT
};

enum
{
	ERROR_FILE_OPEN = 1,
	ERROR_INVALID_FILE,
	ERROR_NEED_HIGHER_VERSION,
	ERROR_DEVICE_OPEN,
	ERROR_COMUNICATION_ERROR,
	ERROR_OLD_NOT_SUPPORTED,
};

typedef struct 
{
	uint8_t id[6]; 
	uint16_t format_version;
	uint8_t sha1[20];
	uint16_t mcu_version;
	uint16_t fw_version;
} __attribute__((packed)) CobraUpdateHeader;

typedef struct
{
	uint8_t  opcode;
	uint8_t  dummy[3];
	uint32_t data;
	uint32_t size;
	uint32_t dummy2;
	uint8_t sha1[20];
	uint32_t dummy3;
} __attribute__((packed)) CobraUpdateOp;

#endif

