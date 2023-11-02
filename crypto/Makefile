CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -Wno-deprecated-declarations -I. -c
LIBFLAGS = -lssl -lcrypto
SRC_FILES = $(wildcard *.c)
OBJ_FILES = $(SRC_FILES:.c=.o)
LIBNAME := libhblk_crypto.a

.PHONY: clean libhblk_crypto.a

all: prog clean

prog: $(OBJ_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) $(LIBFLAGS)

clean: $(OBJ_FILES)
	rm -f $(OBJ_FILES)

$(LIBNAME): $(OBJ_FILES) clean
	ar -rc $(LIBNAME) $(OBJ_FILES)
