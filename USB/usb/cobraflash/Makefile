USBFLAGS=   `libusb-config --cflags`
USBLIBS=    `libusb-config --libs`
EXE_SUFFIX=

# Use the following 3 lines on Windows and comment out the 3 above:
#USBFLAGS=
#USBLIBS=   -lusb
#EXE_SUFFIX= .exe

CC=				gcc
CXX=			g++
CFLAGS=			--std=gnu99 -O2 -Wall $(USBFLAGS) -I../common -DDEBUG
LIBS=			$(USBLIBS)
ARCH_COMPILE=	
ARCH_LINK=		

OBJ=		main.o ../common/cobra.o ../common/sha1.o
PROGRAM=	cobraflash$(EXE_SUFFIX)

all: $(PROGRAM)

$(PROGRAM): $(OBJ)
	$(CC) $(ARCH_LINK) $(CFLAGS) -o $(PROGRAM) $(OBJ) $(LIBS)


strip: $(PROGRAM)
	strip $(PROGRAM)

clean:
	rm -f $(OBJ) $(PROGRAM)

.c.o:
	$(CC) $(ARCH_COMPILE) $(CFLAGS) -c $*.c -o $*.o
