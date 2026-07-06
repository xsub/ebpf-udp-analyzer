BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Werror

.PHONY: all clean

all: udp_ingress.bpf.o

udp_ingress.bpf.o: udp_ingress.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o

