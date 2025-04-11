#ifndef MACHO_BYTE_ORDER_H
#define MACHO_BYTE_ORDER_H

#include <stdio.h>
#include <stdlib.h>
#include <libkern/OSByteOrder.h>

// 8-bit integers needed for CodeDirectory
#define BIG_TO_HOST(n) _Generic((n), \
    int8_t: n, \
    uint8_t: n, \
    int16_t: OSSwapBigToHostInt16(n), \
    uint16_t: OSSwapBigToHostInt16(n), \
    int32_t: OSSwapBigToHostInt32(n), \
    uint32_t: OSSwapBigToHostInt32(n), \
    int64_t: OSSwapBigToHostInt64(n), \
    uint64_t: OSSwapBigToHostInt64(n) \
)

#define HOST_TO_BIG(n) _Generic((n), \
    int8_t: n, \
    uint8_t: n, \
    uint16_t: OSSwapHostToBigInt16(n), \
    int16_t: OSSwapHostToBigInt16(n), \
    int32_t: OSSwapHostToBigInt32(n), \
    uint32_t: OSSwapHostToBigInt32(n), \
    int64_t: OSSwapHostToBigInt64(n), \
    uint64_t: OSSwapHostToBigInt64(n) \
)

#define LITTLE_TO_HOST(n) _Generic((n), \
    int8_t: n, \
    uint8_t: n, \
    int16_t: OSSwapLittleToHostInt16(n), \
    uint16_t: OSSwapLittleToHostInt16(n), \
    int32_t: OSSwapLittleToHostInt32(n), \
    uint32_t: OSSwapLittleToHostInt32(n), \
    int64_t: OSSwapLittleToHostInt64(n), \
    uint64_t: OSSwapLittleToHostInt64(n) \
)

#define HOST_TO_LITTLE(n) _Generic((n), \
    int8_t: n, \
    uint8_t: n, \
    int16_t: OSSwapHostToLittleInt16(n), \
    uint16_t: OSSwapHostToLittleInt16(n), \
    int32_t: OSSwapHostToLittleInt32(n), \
    uint32_t: OSSwapHostToLittleInt32(n), \
    int64_t: OSSwapHostToLittleInt64(n), \
    uint64_t: OSSwapHostToLittleInt64(n) \
)

#define HOST_TO_LITTLE_APPLIER(instance, member) \
    (instance)->member = HOST_TO_LITTLE((instance)->member)

#define HOST_TO_BIG_APPLIER(instance, member) \
    (instance)->member = HOST_TO_BIG((instance)->member)

#define LITTLE_TO_HOST_APPLIER(instance, member) \
    (instance)->member = LITTLE_TO_HOST((instance)->member)

#define BIG_TO_HOST_APPLIER(instance, member) \
    (instance)->member = BIG_TO_HOST((instance)->member)

#define FAT_HEADER_APPLY_BYTE_ORDER(fh, applier) \
    applier(fh, magic); \
    applier(fh, nfat_arch);

#define FAT_ARCH_APPLY_BYTE_ORDER(arch, applier) \
    applier(arch, cputype); \
    applier(arch, cpusubtype); \
    applier(arch, offset); \
    applier(arch, size); \
    applier(arch, align);

#define FAT_ARCH_64_APPLY_BYTE_ORDER(arch, applier) \
    applier(arch, cputype); \
    applier(arch, cpusubtype); \
    applier(arch, offset); \
    applier(arch, size); \
    applier(arch, align); \
    applier(arch, reserved);

#define MACH_HEADER_APPLY_BYTE_ORDER(mh, applier) \
    applier(mh, magic); \
    applier(mh, cputype); \
    applier(mh, cpusubtype); \
    applier(mh, filetype); \
    applier(mh, ncmds); \
    applier(mh, sizeofcmds);

#define LOAD_COMMAND_APPLY_BYTE_ORDER(lc, applier) \
    applier(lc, cmd); \
    applier(lc, cmdsize);

#define LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(lc, applier) \
    applier(lc, cmd); \
    applier(lc, cmdsize); \
    applier(lc, dataoff); \
    applier(lc, datasize);

#define ENCRYPTION_INFO_COMMAND_APPLY_BYTE_ORDER(eic, applier) \
    applier(eic, cmd); \
    applier(eic, cmdsize); \
    applier(eic, cryptoff); \
    applier(eic, cryptsize); \
    applier(eic, cryptid);

#define BLOB_INDEX_APPLY_BYTE_ORDER(bi, applier) \
    applier(bi, type); \
    applier(bi, offset);

#define SUPERBLOB_APPLY_BYTE_ORDER(sb, applier) \
    applier(sb, magic); \
    applier(sb, length); \
    applier(sb, count);

#define GENERIC_BLOB_APPLY_BYTE_ORDER(gb, applier) \
    applier(gb, magic); \
    applier(gb, length);

#define CODE_DIRECTORY_APPLY_BYTE_ORDER(cd, applier) \
    applier(cd, magic); \
    applier(cd, length); \
    applier(cd, version); \
    applier(cd, flags); \
    applier(cd, hashOffset); \
    applier(cd, identOffset); \
    applier(cd, nSpecialSlots); \
    applier(cd, nCodeSlots); \
    applier(cd, codeLimit); \
    applier(cd, hashSize); \
    applier(cd, hashType); \
    applier(cd, platform); \
    applier(cd, pageSize); \
    applier(cd, spare2); \
    applier(cd, scatterOffset); \
    applier(cd, teamOffset);

#define SEGMENT_COMMAND_APPLY_BYTE_ORDER(sc, applier) \
    applier(sc, cmd); \
    applier(sc, cmdsize); \
    applier(sc, fileoff); \
    applier(sc, filesize); \
    applier(sc, vmaddr); \
    applier(sc, vmsize); \
    applier(sc, flags); \
    applier(sc, initprot); \
    applier(sc, maxprot); \
    applier(sc, nsects);

#define SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(sc64, applier) \
    applier(sc64, cmd); \
    applier(sc64, cmdsize); \
    applier(sc64, fileoff); \
    applier(sc64, filesize); \
    applier(sc64, vmaddr); \
    applier(sc64, vmsize); \
    applier(sc64, flags); \
    applier(sc64, initprot); \
    applier(sc64, maxprot); \
    applier(sc64, nsects);

#define SECTION_APPLY_BYTE_ORDER(sc, applier) \
    applier(sc, addr); \
    applier(sc, align); \
    applier(sc, flags); \
    applier(sc, nreloc); \
    applier(sc, offset); \
    applier(sc, reserved1); \
    applier(sc, reserved2); \
    applier(sc, size);

#define SECTION_64_APPLY_BYTE_ORDER(sc64, applier) \
    applier(sc64, addr); \
    applier(sc64, align); \
    applier(sc64, flags); \
    applier(sc64, nreloc); \
    applier(sc64, offset); \
    applier(sc64, reserved1); \
    applier(sc64, reserved2); \
    applier(sc64, reserved3); \
    applier(sc64, size);

#define FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(fse, applier) \
    applier(fse, cmd); \
    applier(fse, cmdsize); \
    applier(fse, vmaddr); \
    applier(fse, fileoff); \
    applier(fse, entry_id.offset); \
    applier(fse, reserved);

#define SYMTAB_COMMAND_APPLY_BYTE_ORDER(symt, applier) \
    applier(symt, cmd); \
    applier(symt, cmdsize); \
    applier(symt, nsyms); \
    applier(symt, stroff); \
    applier(symt, strsize); \
    applier(symt, symoff);

#define NLIST_APPLY_BYTE_ORDER(nl, applier) \
    applier(nl, n_un.n_strx); \
    applier(nl, n_type); \
    applier(nl, n_sect); \
    applier(nl, n_desc); \
    applier(nl, n_value);

#define NLIST_64_APPLY_BYTE_ORDER(nl, applier) \
    applier(nl, n_un.n_strx); \
    applier(nl, n_type); \
    applier(nl, n_sect); \
    applier(nl, n_desc); \
    applier(nl, n_value);

#define DYLIB_APPLY_BYTE_ORDER(dylib, applier) \
    applier(dylib, name.offset); \
    applier(dylib, timestamp); \
    applier(dylib, current_version); \
    applier(dylib, compatibility_version);

#define DYLIB_COMMAND_APPLY_BYTE_ORDER(dycmd, applier) \
    LOAD_COMMAND_APPLY_BYTE_ORDER(dycmd, applier); \
    DYLIB_APPLY_BYTE_ORDER((&dycmd->dylib), applier);

#define RPATH_COMMAND_APPLY_BYTE_ORDER(rpcmd, applier) \
    LOAD_COMMAND_APPLY_BYTE_ORDER(rpcmd, applier); \
    applier(rpcmd, path.offset);

#endif // MACHO_BYTE_ORDER_H
