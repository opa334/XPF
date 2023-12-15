CC = clang


CFLAGS = -Iexternal/include -O2
LDFLAGS = 

all: libxpf.dylib xpf_test

libxpf.dylib: $(wildcard src/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(LDFLAGS) -dynamiclib -install_name @executable_path/libxpf.dylib -o $@ $^

xpf_test: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lxpf -o $@ $^

clean:
	@rm -f libxpf.dylib
	@rm -f xpf_test