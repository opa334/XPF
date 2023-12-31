#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/PatchFinder.h>
#include <choma/MachOByteOrder.h>
#include <mach/machine.h>
#include <sys/_types/_null.h>
#include "xpf.h"

#include "ppl.h"
#include "non_ppl.h"
#include "common.h"
#include "pac_bypass.h"

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
		gXPF.kernelTextSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT_EXEC", "__text");
		gXPF.kernelPPLTextSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__PPLTEXT", "__text");
		gXPF.kernelStringSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__cstring");
		gXPF.kernelDataConstSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__DATA_CONST", "__const");
		gXPF.kernelOSLogSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__os_log");
	}
	else {
		gXPF.kernelTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT_EXEC", "__text");
		gXPF.kernelPPLTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__PPLTEXT", "__text");
		gXPF.kernelStringSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__cstring");
		gXPF.kernelDataConstSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__DATA_CONST", "__const");
		gXPF.kernelOSLogSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__os_log");
	}

	pfsec_set_cached(gXPF.kernelTextSection, true);
	if (gXPF.kernelPPLTextSection) pfsec_set_cached(gXPF.kernelPPLTextSection, true);
	pfsec_set_cached(gXPF.kernelStringSection, true);
	pfsec_set_cached(gXPF.kernelDataConstSection, true);
	pfsec_set_cached(gXPF.kernelOSLogSection, true);

	gXPF.kernelBase = UINT64_MAX;
	gXPF.kernelEntry = 0;
	macho_enumerate_load_commands(gXPF.kernel, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segCmd = (struct segment_command_64 *)cmd;
			SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segCmd, LITTLE_TO_HOST_APPLIER);
			if (segCmd->vmaddr < gXPF.kernelBase) {
				gXPF.kernelBase = segCmd->vmaddr;
			}
		}
		else if (loadCommand.cmd == LC_UNIXTHREAD) {
			uint8_t *cmdData = ((uint8_t *)cmd + sizeof(struct thread_command));
			uint8_t *cmdDataEnd = ((uint8_t *)cmd + loadCommand.cmdsize);

			while (cmdData < cmdDataEnd) {
				uint32_t flavor = LITTLE_TO_HOST(*(uint32_t *)cmdData);
				uint32_t count = LITTLE_TO_HOST(*(uint32_t *)(cmdData + 4));
				if (flavor == ARM_THREAD_STATE64) {
					arm_thread_state64_t *threadState = (arm_thread_state64_t *)(cmdData + 8);
					gXPF.kernelEntry = LITTLE_TO_HOST(arm_thread_state64_get_pc(*threadState));
				}
				cmdData += (8 + count);
			}
		}
	});

	if (gXPF.kernelBase == UINT64_MAX) {
		printf("XPF Error: Unable to find kernel base\n");
		return -1;
	}
	if (!gXPF.kernelEntry) {
		printf("XPF Error: Unable to find kernel entry\n");
		return -1;
	}

	xpf_ppl_init();
	xpf_non_ppl_init();
	xpf_common_init();
	xpf_pac_bypass_init();

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

uint64_t xpfsec_read_ptr(PFSection *section, uint64_t vmaddr)
{
	uint64_t r = pfsec_read64(gXPF.kernelDataConstSection, vmaddr);
	if ((r & 0xff00000000000000) == 0x8000000000000000) {
		r &= 0x00000000ffffffff;
		r += 0xfffffff007004000;
	}
	return r;
}

void xpf_stop(void)
{
	if (gXPF.kernelStringSection) {
		pfsec_free(gXPF.kernelStringSection);
	}
	if (gXPF.kernelTextSection) {
		pfsec_free(gXPF.kernelTextSection);
	}
	if (gXPF.kernelOSLogSection) {
		pfsec_free(gXPF.kernelOSLogSection);
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