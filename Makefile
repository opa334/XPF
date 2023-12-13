CC = clang


CFLAGS = -Iexternal/include -O2
LDFLAGS = 

all: libkpf.dylib kpf_test

libkpf.dylib: $(wildcard src/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(LDFLAGS) -dynamiclib -install_name @executable_path/libkpf.dylib -o $@ $^

kpf_test: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lkpf -o $@ $^

clean:
	@rm -f libkpf.dylib
	@rm -f kpf_test