SRC                 = $(wildcard src/*.c) $(wildcard src/*/*.c) $(wildcard src/*/*/*.c)
CFLAGS              = -Wall -Wextra

INJECTOR64 = ./bin/x86_64/injector.exe
OBJ64      = $(addprefix build/x86_64/, $(SRC:.c=.o))
CC64       = x86_64-w64-mingw32-gcc

all: $(INJECTOR64)

$(INJECTOR64): $(OBJ64)
	mkdir -p $(shell dirname $(INJECTOR64))
	$(CC64) -D_WIN64 $(CFLAGS) $(OBJ64) -o $(INJECTOR64)

build/x86_64/%.o: %.c
	mkdir -p $(shell dirname $@)
	$(CC64) -D_WIN64 $(CFLAGS) -c $< -o $@

clean:
	rm -rf build/x86_64/*
	rm -rf build/x86/*

fclean: clean
	rm -rf bin/x86_64/*
	rm -rf bin/x86/*

re: fclean all
