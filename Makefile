CC = clang

CHOMA_DYLIB_PATH ?= external/ios/lib
CFLAGS = -O2
CFLAGS_MACOS = -Iexternal/include
CFLAGS_IOS = -Iexternal/ios/include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=15.0 -arch arm64 -arch arm64e
LDFLAGS = -lcompression

all: libxpf_macos.dylib libxpf.dylib xpf_test_macos xpf_test_ios

libxpf_macos.dylib: $(wildcard src/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -dynamiclib -install_name @loader_path/libxpf_macos.dylib -o $@ $^

libxpf.dylib: $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -dynamiclib -L$(CHOMA_DYLIB_PATH) -lchoma -install_name @loader_path/libxpf.dylib -o $@ $^
	ldid -S $@

xpf_test_macos: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -L. -lxpf_macos -o $@ $^

xpf_test_ios: $(wildcard src/cli/*.c) 
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -L. -lxpf -o $@ $^

clean:
	@rm -f libxpf.dylib
	@rm -f libxpf_macos.dylib
	@rm -f xpf_test_ios
	@rm -f xpf_test_macos