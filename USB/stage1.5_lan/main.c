#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <lv2/synchronization.h>
#include <lv2/usb.h>
#include <lv2/patch.h>
#include <lv2/io.h>

#include <lv1/lv1.h>

#include <debug.h>

#include "gelic.h"

#define PAYLOAD_SIZE			(135000)

#ifdef DEBUG
#define DPRINTF _debug_printf
#else
#define DPRINTF(...)
#endif

#define stage1_ep_pipe_symbol		0x7FC1B0
#define stage1_usb_port_symbol		0x7FC1E0
#define stage1_usb_queue_symbol		0x7FC1F0 
#define stage1_usb_driver_symbol	0x7FC190 /* direct pointer */
#define stage1_hv_lpar_symbol		0x7FC1C8

static INLINE uint32_t lwz(uint64_t addr)
{
	return *(uint32_t *)MKA(addr);
}

static INLINE uint64_t ld(uint64_t addr)
{
	return *(uint64_t *)MKA(addr);
}

void stage1_finish(void)
{	
	cellUsbdClosePipe(lwz(stage1_ep_pipe_symbol));
	event_port_disconnect((void *)ld(stage1_usb_port_symbol));
	event_port_destroy((void *)ld(stage1_usb_port_symbol));
	event_queue_destroy((void *)ld(stage1_usb_queue_symbol));
	cellUsbdUnregisterLdd((void *)MKA(stage1_usb_driver_symbol));	
}

static INLINE void setup_keys(void)
{

	uint8_t teaKey[16] = { TEA_CODE_KEY };
	uint64_t *key64 = (uint64_t *)teaKey;
	lv1_create_repository_node(1, 2, 3, 4, key64[0], key64[1]);
}

int main(void)
{
	u8 *payload, *stage2;
	int payload_size, result;
	uint64_t hv_lpar;
	
#ifdef DEBUG
	debug_init();	
#endif

	DPRINTF("Stage 1.5 lan hello.\n");
		
	stage1_finish();
	hv_lpar = ld(stage1_hv_lpar_symbol);
	
	setup_keys();
		
	result = gelic_init();
	if (result != 0)
		goto error;
	
	payload = (void *)MKA(0x700000);//alloc(PAYLOAD_SIZE, 0x27);
	if (!payload)
		goto error;
	
	payload_size = gelic_recv_data(payload, PAYLOAD_SIZE);
	if (payload_size <= 0)
		goto error;	
		
	DPRINTF("Receive data: %d\n", payload_size);
	
	stage2 = alloc(payload_size, 0x27);
	if (!stage2)
		goto error;
	
	memcpy(stage2, payload, payload_size);
	clear_icache(stage2, payload_size);
	
	//dealloc(payload, 0x27);

	result = gelic_deinit();
	if (result != 0)
		goto error;

	/*result = mm_deinit();
	if (result != 0)
		goto error;*/

	f_desc_t desc;	
	desc.addr = stage2;
	
	DPRINTF("Calling stage2...\n");
	debug_end();
	void (* stage2_func)(uint64_t) = (void *)&desc;
	stage2_func(hv_lpar);	
	
	return 0;

error:

	lv1_panic(0);
	return -1;
}
