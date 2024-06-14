CC := $(shell which clang)

CFLAGS := -O3 -g -target bpf --std gnu17
CFLAGS += -Wall -Wextra -Wpedantic -Wno-pointer-arith -Wno-gnu-zero-variadic-macro-arguments
CFLAGS += -DDEBUG

.PHONY: all clean

all: af_xdp.o

clean:
	$(RM) as_xdp.o
