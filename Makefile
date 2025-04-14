CC = clang

DYNLINK_CHOMA ?= 0
CHOMA_PATH ?= $(shell pwd)/external/ChOma
CFLAGS = -O2 -framework Foundation
CFLAGS_MACOS = -Iexternal/include
CFLAGS_IOS = -Iexternal/include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=15.0 -arch arm64 -arch arm64e
LDFLAGS = -lcompression

all: external/include libxpf_macos.dylib libxpf_ios.dylib xpf_test_macos xpf_test_ios

external/include:
	@mkdir -p external/include
	@ln -s $(CHOMA_PATH)/src external/include/choma

ifeq ($(DYNLINK_CHOMA), 1)

libxpf_macos.dylib: $(wildcard src/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -dynamiclib -install_name @loader_path/libxpf_macos.dylib -o $@ $^

libxpf_ios.dylib: $(wildcard src/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -dynamiclib -L$(CHOMA_DYLIB_PATH) -lchoma -install_name @loader_path/libxpf.dylib -o $@ $^
	ldid -S $@

xpf_test_macos: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -L. -lxpf_macos -o $@ $^

xpf_test_ios: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -L. -lxpf_ios -o $@ $^
	@ldid -S $@

else

libxpf_macos.dylib: $(wildcard src/*.c $(CHOMA_PATH)/src/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -dynamiclib -install_name @loader_path/libxpf_macos.dylib -o $@ $^

libxpf_ios.dylib: $(wildcard src/*.c $(CHOMA_PATH)/src/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -dynamiclib -install_name @loader_path/libxpf.dylib -o $@ $^
	@ldid -S $@

xpf_test_macos: $(wildcard src/cli/*.c external/lib/libchoma.a)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) $(LDFLAGS) -L. -lxpf_macos -o $@ $^

xpf_test_ios: $(wildcard src/cli/*.c)
	$(CC) $(CFLAGS) $(CFLAGS_IOS) $(LDFLAGS) -L. -lxpf_ios -o $@ $^
	@ldid -S $@

endif

clean:
	@rm -rf external/include
	@rm -f libxpf.dylib
	@rm -f libxpf_macos.dylib
	@rm -f xpf_test_ios
	@rm -f xpf_test_macos