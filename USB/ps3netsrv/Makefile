OS =  linux
BUILD_TYPE = debug

OUTPUT := ps3netsrv
OBJS=main.o compat.o File.o VIsoFile.o
CFLAGS=-Wall -I. -std=gnu99 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS=-L. 
LIBS = -lstdc++

ifeq ($(OS), linux)
LIBS += -lpthread
endif

ifeq ($(OS), windows)
CC = gcc
CXX = g++
LIBS += -lws2_32
OUTPUT := $(OUTPUT).exe
endif

ifeq ($(OS), cross)
CC=i586-pc-mingw32-gcc
CXX=i586-pc-mingw32-g++
LIBS += -lws2_32
OUTPUT := $(OUTPUT).exe
endif

ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG
endif

ifeq ($(BUILD_TYPE), debug_static)
CFLAGS += -DDEBUG -static
endif

ifeq ($(BUILD_TYPE), release)
endif

ifeq ($(BUILD_TYPE), release_static)
CFLAGS += -static
endif

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT) *.o

$(OUTPUT): $(OBJS)
	$(LINK.c) $(LDFLAGS) -o $@ $^ $(LIBS)
