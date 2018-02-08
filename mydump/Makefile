CC := gcc
CFLAGS := -Wall -Werror
DFLAGS := -DCOLOR -g -DDEBUG
INFOFLAGS := -DCOLOR -DINFO
BIN := mydump
SRC := $(wildcard *.c)
LIB := -lpcap

.PHONY: clean all info

debug: CFLAGS += $(DFLAGS)
debug: all
info: CFLAGS += $(INFOFLAGS)
info: all

all: $(BIN)

mydump: $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

clean:
	rm -f $(BIN) *.o