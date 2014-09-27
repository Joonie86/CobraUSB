OUTPUT=st15cipher
OBJS=main.o 
CFLAGS=-Wall -I. --std=gnu99
LDFLAGS=-L. -lstdc++

all: $(OUTPUT)

i8051.o: vm.h rom.h opcodes.c

clean:
	rm -f $(OUTPUT) *.o

$(OUTPUT): $(OBJS)
	$(LINK.c) $(LDFLAGS) -o $@ $^ $(LIBS)
