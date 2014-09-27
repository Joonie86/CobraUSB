OUTPUT=sprx_cipher2
OBJS=main.o 
CFLAGS=-Wall -I. --std=gnu99
LDFLAGS=-L. -lstdc++
CC=gcc

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT) *.o

$(OUTPUT): $(OBJS)
	$(LINK.c) $(LDFLAGS) -o $@ $^ $(LIBS)
