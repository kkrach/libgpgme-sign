# Makefile for libgpgme-sign

CC=gcc

TARGET=gpgme-sign

SCRS=main.c
OBJS=$(SCRS:.c=.o)
CFLAGS  = `gpgme-config --cflags`
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -Wall -Werror -g
LDFLAGS =`gpgme-config --thread=pthread --libs`

default: all
all: $(TARGET)


$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)


clean:
	rm -rf $(TARGET) $(OBJS)

sign: $(TARGET)
	./$(TARGET) --key 8EF5C816 README.md

.PONY: clean sign
