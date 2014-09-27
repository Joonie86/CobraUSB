#include <lv2/lv2.h>
#include <lv2/error.h>
#include <lv2/libc.h>
#include <lv2/usb.h>
#include <lv2/synchronization.h>
#include <lv2/thread.h>
#include <lv2/security.h>
#include <lv2/memory.h>
#include <cryptcode/cryptcode.h>
#include "common.h"
#include "cobra.h"
#include "config.h"
#include "storage_ext.h"
#include "crypto.h"

#ifndef BIT
#define BIT(var, bit)				((var >> (bit)) & 1)
#endif
#define HS_SCRAMBLE(b)				((BIT(b, 1) << 0) | (BIT(b, 0) << 1) | (BIT(b, 3) << 2) | (BIT(b, 2) << 3) | (BIT(b, 5) << 4) | (BIT(b, 4) << 5) | (BIT(b, 7) << 6) | (BIT(b, 6) << 7))

static int device_connected, ep_pipe;
static uint64_t dynamic_handshake;
static mutex_t mutex;
static event_port_t port;
static event_queue_t queue;

ENCRYPTED_DATA uint8_t h_key0[] = { 0x04, 0xB8, 0xEB, 0x30, 0xD8, 0xC0, 0x0B, 0x03 };

ENCRYPTED_CALLBACK(void, device_callback, (int result, int count, void *arg))
{
	//DPRINTF("Usb result = %d\n", result);
	event_port_send(port, result, 0, 0);
}

ENCRYPT_PATCHED_FUNCTION(device_callback);

ENCRYPTED_CALLBACK(int, device_probe, (int dev_id))
{
	uint8_t *desc;
	desc = cellUsbdScanStaticDescriptor(dev_id, NULL, 1);
	if (!desc)
		return -1;
	
	if ((*(uint32_t *)&desc[8] == 0xAAAABAC0))
	{
		return 0;
	}
	
	return -1;
}

ENCRYPT_PATCHED_FUNCTION(device_probe);

ENCRYPTED_CALLBACK(int, device_attach, (int dev_id))
{
	ep_pipe = cellUsbdOpenPipe(dev_id, NULL);
	
	if (ep_pipe < 0)
		return -1;
	
	DPRINTF("Device connected.\n");	
	device_connected = 1;
	cobra_ps3_set();
	read_cobra_config();
			
	return 0;
}

ENCRYPT_PATCHED_FUNCTION(device_attach);

ENCRYPTED_CALLBACK(int, device_remove, (int dev_id))
{
	DPRINTF("Device disconnected.\n");
	device_connected = 0;
	return 0;
}

ENCRYPT_PATCHED_FUNCTION(device_remove);

static CellUsbdLddOps usb_driver = 
{
	"",
	device_probe,
	device_attach,
	device_remove
};

static INLINE void swap64_p(void *p)
{
	uint64_t *p64 = (uint64_t *)p;
	uint64_t data = *p64;
	
	uint64_t ret = (data << 56) & 0xff00000000000000ULL;
	ret |= ((data << 40) & 0x00ff000000000000ULL);
	ret |= ((data << 24) & 0x0000ff0000000000ULL);
	ret |= ((data << 8) & 0x000000ff00000000ULL);
	ret |= ((data >> 8) & 0x00000000ff000000ULL);
	ret |= ((data >> 24) & 0x0000000000ff0000ULL);
	ret |= ((data >> 40) & 0x000000000000ff00ULL);
	ret |= ((data >> 56) & 0x00000000000000ffULL);
	*p64 = ret;
}

static INLINE uint8_t reverse_bits(uint8_t b)
{
	b = ((b * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32;
	return b;
}

static void translate_buffer(void *in, void *out)
{
	uint8_t *in8 = (uint8_t *)in;
	uint8_t *out8 = (uint8_t *)out;
	
	for (int i = 0; i < 8; i++)
	{
		out8[i] = reverse_bits(in8[i]);
	}
	
	swap64_p(out);
}

ENCRYPTED_SUICIDAL_FUNCTION(void, cobra_device_init, (void))
{
	uint32_t n;
	
	device_connected = 0;
	mutex_create(&mutex, SYNC_PRIORITY, SYNC_NOT_RECURSIVE);
	event_port_create(&port, EVENT_PORT_LOCAL);
	event_queue_create(&queue, SYNC_PRIORITY, 1, 1);
	event_port_connect(port, queue);
	cellUsbdRegisterLdd(&usb_driver);
	
	while (!device_connected)
		timer_usleep(1000);
	
	des_init();
	encrypted_data_toggle(h_key0, sizeof(h_key0));
	
	get_pseudo_random_number(&n, sizeof(n));
	
	n = n&0x3F;
	if (n == 0)
		n = 61;
	
	//DPRINTF("n = %d\n", n);
	
	for (uint8_t i = 0; i < n; i++)
	{
		des_context ctx;
		uint8_t rnd[8], buf1[8], buf2[8];
		
		get_pseudo_random_number(rnd, sizeof(rnd));
		
		translate_buffer(rnd, buf1);
		cobra_scp_handshake(COBRA_SCP_HANDSHAKE_KEY_0, 0, 0, buf1, buf1);
		translate_buffer(buf1, buf1);
		
		for (uint8_t j = 0; j < 8; j++)
		{
			buf2[j] = HS_SCRAMBLE(rnd[j]);
		}
		
		des_setkey_enc(&ctx, h_key0);
		des_crypt_ecb(&ctx, buf2, buf2);
		
		//DPRINT_HEX(buf1, 8);
		//DPRINT_HEX(buf2, 8);
		if (memcmp(buf1, buf2, 8) != 0)
		{
			extern uint64_t _start;
			
			DPRINTF("Panic handshake!\n");			
			memset(&_start, 0, 128*1024);
			while(1);
		}
	}
	
	encrypted_data_destroy(h_key0, sizeof(h_key0));
	des_destroy();	
	
	cobra_scp_handshake(COBRA_SCP_HANDSHAKE_KEY_0, 1, 0, &dynamic_handshake, &dynamic_handshake);
	//translate_buffer(&dynamic_handshake, &dynamic_handshake);
	DPRINTF("dynamic handshake: %lx\n", dynamic_handshake);
}

ENCRYPTED_FUNCTION(int, cobra_usb_command, (uint8_t command, uint8_t bmRequestType, uint32_t addr, void *buf, uint16_t size))
{
	if (!device_connected)
		return ENODEV;
	
	UsbDeviceRequest req;
	event_t event;
	int ret;
	
	req.bmRequestType = bmRequestType;
	req.bRequest = command;
	req.wValue = (addr >> 16);
	req.wIndex = (addr & 0xFFFF);
	req.wLength = size;
		
	mutex_lock(mutex, 0);
	ret = cellUsbdControlTransfer(ep_pipe, &req, buf, device_callback, NULL);
	if (ret < 0)
	{
		mutex_unlock(mutex);
		return ret;
	}
	
	//DPRINTF("ret = %x\n", ret);
		
	event_queue_receive(queue, &event, 0);
	if (!device_connected)
		ret = ENODEV;
	else
		ret = (int)(int64_t)event.data1;
	
	mutex_unlock(mutex);	
	return ret;
}

ENCRYPTED_FUNCTION(int, cobra_spi_flash_read, (uint32_t addr, void *buf, uint32_t size, int decrypt))
{
	int ret;
	uint8_t *buf8 = (uint8_t *)buf;
	uint32_t remaining = size;
	
	for (int i = 0; i < size; i += 4096, addr += 4096, remaining -= 4096)
	{
		ret = cobra_usb_command((decrypt) ? CMD_SPI_FLASH_READ_AND_DECRYPT2 : CMD_SPI_FLASH_READ, TYPE_DEV2HOST, addr, 
					buf8+i, (remaining > 4096) ? 4096 : remaining);	
					
		if (ret != 0)
			return ret;
	}
	
	return ret;
}

ENCRYPTED_FUNCTION(int, cobra_scp_handshake, (uint8_t key, uint8_t dynamic, uint8_t function, void *in, void *out))
{
	int ret;
	
	ret = cobra_usb_command(CMD_SCP_SET_BUFFER, TYPE_HOST2DEV, 0, in, 8);
	if (ret == 0)
		ret = cobra_usb_command(CMD_SCP_HANDSHAKE, TYPE_DEV2HOST, (function << 16) | (dynamic << 8) | key, out, 8);
	
	return ret;
}

ENCRYPTED_FUNCTION(int, sys_cobra_usb_command, (uint8_t command, uint8_t bmRequestType, uint32_t addr, void *buf, uint16_t size))
{
	void *kbuf;
	int ret;
	
	buf = get_secure_user_ptr(buf);
	
	if (size > 4096)
		return EINVAL;
	
	if (size > 0)
	{	
		ret = page_allocate_auto(NULL, 4096, 0x2F, &kbuf);
		if (ret != 0)
			return ret;
	}
	else
	{
		kbuf = NULL;
	}
	
	if (!(bmRequestType & USB_REQTYPE_DIR_TO_HOST))
	{
		ret = copy_from_user(buf, kbuf, size);
		if (ret != 0)
		{
			page_free(NULL, kbuf, 0x2F);
			return ret;
		}		
	}
	else
	{
		memset(kbuf, 0, size);
	}
	
	ret = cobra_usb_command(command, bmRequestType, addr, kbuf, size);
	if (ret == 0)
	{
		if (bmRequestType & USB_REQTYPE_DIR_TO_HOST)
		{
			ret = copy_to_user(kbuf, buf, size);				
		}
	}
	
	if (kbuf)
	{
		page_free(NULL, kbuf, 0x2F);
	}
	
	return ret;	
}


