CC=ppu-gcc
STRIP=ppu-strip
OBJCOPY=ppu-objcopy
CFLAGS+=-mno-toc -Os $(INC) -std=gnu99
LDFLAGS=-Tldscript.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,--gc-sections
INC=-I. 
TARGET=xtea
CIPHER=../xtea_cipher/xtea_cipher
KEYS=xtea_keys
HEADER=../loader/xtea.h

SRC_ASM= 

SRC_C= xtea.c

OBJ=$(SRC_ASM:.S=.o) $(SRC_C:.c=.o)

ELF=$(TARGET).elf
BIN=$(TARGET).bin

all: $(BIN)

$(BIN): $(ELF)
	$(STRIP) -s $^
	$(OBJCOPY) -j .start -j .text -O binary $^ $@	
	$(CIPHER) $@ $(KEYS) $(HEADER)

$(ELF): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $^

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f $(BIN) $(ELF) $(OBJ)
