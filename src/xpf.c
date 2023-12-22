#include "choma/FAT.h"
#include "choma/MachO.h"
#include "choma/PatchFinder.h"
#include <mach/machine.h>
#include <sys/_types/_null.h>
#include "xpf.h"

#include "ppl.h"

XPF gXPF;

int xpf_start_with_kernel_path(const char *kernelPath)
{
	FAT *candidate = fat_init_from_path(kernelPath);
	if (!candidate) return -1;

	MachO *machoCandidate = NULL;
	machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
	if (!machoCandidate) {
		machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
		if (!machoCandidate) {
			machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, 0xC0000002);
		}
	}
	if (!machoCandidate) return -1;

	gXPF.kernelContainer = candidate;
	gXPF.kernel = machoCandidate;
	gXPF.kernelIsFileset = macho_get_filetype(gXPF.kernel) == MH_FILESET;

	if (gXPF.kernelIsFileset) {
		gXPF.kernelTextSection = pf_section_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT_EXEC", "__text");
		gXPF.kernelStringSection = pf_section_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__cstring");
		gXPF.kernelDataConstSection = pf_section_init_from_macho(gXPF.kernel, "com.apple.kernel", "__DATA_CONST", "__const");
	}
	else {
		gXPF.kernelTextSection = pf_section_init_from_macho(gXPF.kernel, NULL, "__TEXT_EXEC", "__text");
		gXPF.kernelStringSection = pf_section_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__cstring");
		gXPF.kernelDataConstSection = pf_section_init_from_macho(gXPF.kernel, NULL, "__DATA_CONST", "__const");
	}

	xpf_ppl_init();

	return 0;
}

uint64_t xpf_find_sysent(void)
{
	return 0;
}

void xpf_item_register(const char *name, void *finder, void *ctx)
{
	XPFItem *newItem = malloc(sizeof(XPFItem));
	newItem->name = name;
	newItem->ctx = ctx;
	newItem->finder = finder;
	newItem->cache = 0;
	newItem->cached = false;

	XPFItem *lastItem = gXPF.firstItem;
	XPFItem *item = lastItem;
	while (item) {
		lastItem = item;
		item = item->nextItem;
	}
	if (!lastItem) {
		gXPF.firstItem = newItem;
	}
	else {
		lastItem->nextItem = newItem;
	}
}

uint64_t xpf_resolve_item(const char *name)
{
	XPFItem *item = gXPF.firstItem;
	while (item) {
		if (!strcmp(item->name, name)) {
			if (!item->cached) {
				item->cache = item->finder(item->ctx);
				item->cached = true;
			}
			return item->cache;
		}
		item = item->nextItem;
	}
	return 0;
}

uint64_t xpf_section_read_ptr(PFSection *section, uint64_t vmaddr)
{
	uint64_t r = pf_section_read64(gXPF.kernelDataConstSection, vmaddr);
	if ((r & 0xff00000000000000) == 0x8000000000000000) {
		r &= 0x00000000ffffffff;
		r += 0xfffffff007004000;
	}
	return r;
}

void xpf_stop(void)
{
	if (gXPF.kernelStringSection) {
		pf_section_free(gXPF.kernelStringSection);
	}
	if (gXPF.kernelTextSection) {
		pf_section_free(gXPF.kernelTextSection);
	}
	if (gXPF.kernelContainer) {
		fat_free(gXPF.kernelContainer);
	}

	XPFItem *item = gXPF.firstItem;
	while (item) {
		XPFItem *curItem = item;
		item = item->nextItem;
		free(curItem);
	}
}