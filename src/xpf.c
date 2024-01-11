#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/PatchFinder.h>
#include <choma/MachOByteOrder.h>
#include <choma/BufferedStream.h>
#include <mach/machine.h>
#include <sys/_types/_null.h>
#include "xpf.h"
#include "decompress.h"

#include "ppl.h"
#include "non_ppl.h"
#include "common.h"
#include "bad_recovery.h"

bool xpf_supported_always(void)
{
	return true;
}

bool xpf_supported_15down(void)
{
	return strcmp(gXPF.darwinVersion, "22.0.0") < 0;
}

bool xpf_supported_16up(void)
{
	return strcmp(gXPF.darwinVersion, "22.0.0") >= 0;
}

XPFSet gBaseSet = {
	.name="base",
	.supported=xpf_supported_always,
	.metrics={
		"kernelConstant.kernel_el",
		"kernelSymbol.allproc",
		"kernelSymbol.kalloc_data_external",
		"kernelSymbol.kfree_data_external",
		NULL
	}
};

XPFSet gTranslationSet = {
	.name="translation",
	.supported=xpf_supported_always,
	.metrics={
		"kernelSymbol.cpu_ttep",
		"kernelSymbol.gVirtBase",
		"kernelSymbol.gPhysBase",
		"kernelSymbol.gPhysSize",
		"kernelSymbol.ptov_table",
		"kernelConstant.pointer_mask",
		"kernelConstant.T1SZ_BOOT",
		"kernelConstant.ARM_TT_L1_INDEX_MASK",
		NULL
	}
};

XPFSet gPhysmapSet = {
	.name="physmap",
	.supported=xpf_supported_always,
	.metrics={
		"kernelSymbol.vm_page_array_beginning_addr",
		"kernelSymbol.vm_page_array_ending_addr",
		"kernelSymbol.vm_first_phys_ppnum",
		"kernelSymbol.vm_first_phys",
		"kernelSymbol.vm_last_phys",
		"kernelSymbol.pp_attr_table",
		"kernelSymbol.pv_head_table",
		"kernelSymbol.ptov_table",
		NULL
	}
};

XPFSet gStructSet = {
	.name="struct",
	.supported=xpf_supported_always,
	.metrics={
		"kernelStruct.proc.struct_size",
		"kernelStruct.task.itk_space",
		"kernelStruct.vm_map.pmap",
		NULL
	}
};

XPFSet gTrustcache15Set = {
	.name="trustcache",
	.supported=xpf_supported_15down,
	{
		"kernelSymbol.pmap_image4_trust_caches",
		NULL
	}
};

XPFSet gTrustcache16Set = {
	.name="trustcache",
	xpf_supported_16up,
	.metrics={
		"kernelSymbol.ppl_trust_cache_rt",
		NULL
	}
};

XPFSet gBadRecoverySet = {
	.name="badRecovery",
	.supported=xpf_bad_recovery_supported,
	.metrics={
		"kernelSymbol.hw_lck_ticket_reserve_orig_allow_invalid",
		"kernelGadget.hw_lck_ticket_reserve_orig_allow_invalid_signed",
		"kernelGadget.br_x22",
		"kernelSymbol.exception_return",
		"kernelGadget.exception_return_after_check",
		"kernelGadget.exception_return_after_check_no_restore",
		"kernelGadget.ldp_x0_x1_x8",
		"kernelGadget.str_x8_x9",
		"kernelGadget.str_x0_x19_ldr_x20",
		"kernelGadget.pacda",
		"kernelSymbol.ml_sign_thread_state",
		"kernelStruct.thread.recover",
		"kernelStruct.thread.machine_kstackptr",
		"kernelStruct.thread.machine_CpuDatap",
		"kernelStruct.thread.machine_contextData",
		NULL
	}
};

XPFSet gPhysRWSet = {
	.name="physrw",
	.supported=xpf_supported_always,
	.metrics={
		NULL,
	}
};

XPFSet gPerfKRWSet = {
	.name="perfkrw",
	.supported=xpf_supported_always,
	.metrics={
		"kernelSymbol.perfmon_dev_open",
		"kernelSymbol.perfmon_devices",
		"kernelSymbol.vn_kqfilter",
		"kernelSymbol.cdevsw",
		NULL
	},
};

XPFSet *gSets[] = {
	&gBaseSet,
	&gTranslationSet,
	&gPhysmapSet,
	&gStructSet,
	&gTrustcache15Set,
	&gTrustcache16Set,
	&gBadRecoverySet,
	&gPhysRWSet,
	&gPerfKRWSet,
};

XPF gXPF = { 0 };

int xpf_start_with_kernel_path(const char *kernelPath)
{
	gXPF.kernelFd = open(kernelPath, O_RDONLY);
	if (gXPF.kernelFd < 0) {
		xpf_set_error("Failed to open kernelcache");
		return -1;
	}

	struct stat s;
	fstat(gXPF.kernelFd, &s);
	gXPF.kernelSize = s.st_size;
	gXPF.mappedKernel = mmap(NULL, gXPF.kernelSize, PROT_READ, MAP_PRIVATE, gXPF.kernelFd, 0);
	if (gXPF.mappedKernel == MAP_FAILED) {
		xpf_set_error("Failed to map kernelcache");
		return -1;
	}

	MemoryStream *stream = NULL;
	if (LITTLE_TO_HOST(*(uint32_t *)(gXPF.mappedKernel)) == MH_MAGIC_64) {
		stream = buffered_stream_init_from_buffer_nocopy(gXPF.mappedKernel, gXPF.kernelSize, 0);
	}
	else {
		gXPF.decompressedKernel = kdecompress(gXPF.mappedKernel, gXPF.kernelSize, &gXPF.decompressedKernelSize);
		if (gXPF.decompressedKernel) {
			stream = buffered_stream_init_from_buffer_nocopy(gXPF.decompressedKernel, gXPF.decompressedKernelSize, 0);
		}
	}

	FAT *candidate = fat_init_from_memory_stream(stream);
	if (!candidate) {
		xpf_set_error("Failed to load kernel macho");
		return -1;
	}

	MachO *machoCandidate = NULL;
	gXPF.kernelIsArm64e = false;
	machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
	if (!machoCandidate) {
		gXPF.kernelIsArm64e = true;
		machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
		if (!machoCandidate) {
			machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, 0xC0000002);
		}
	}
	if (!machoCandidate) {
		xpf_set_error("Failed to load kernel macho");
		return -1;
	}

	gXPF.kernelContainer = candidate;
	gXPF.kernel = machoCandidate;
	gXPF.kernelIsFileset = macho_get_filetype(gXPF.kernel) == MH_FILESET;

	if (gXPF.kernelIsFileset) {
		gXPF.kernelTextSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT_EXEC", "__text");
		gXPF.kernelPPLTextSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__PPLTEXT", "__text");
		gXPF.kernelStringSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__cstring");
		gXPF.kernelConstSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__const");
		gXPF.kernelDataConstSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__DATA_CONST", "__const");
		gXPF.kernelDataSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__DATA", "__data");
		gXPF.kernelOSLogSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__TEXT", "__os_log");
		gXPF.kernelBootdataInit = pfsec_init_from_macho(gXPF.kernel, "com.apple.kernel", "__BOOTDATA", "__init");
		gXPF.kernelAMFITextSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text");
		gXPF.kernelAMFIStringSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.driver.AppleMobileFileIntegrity", "__TEXT", "__cstring");
		gXPF.kernelInfoPlistSection = pfsec_init_from_macho(gXPF.kernel, "com.apple.security.AppleImage4", "__TEXT", "__info_plist");
	}
	else {
		gXPF.kernelTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT_EXEC", "__text");
		gXPF.kernelPPLTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__PPLTEXT", "__text");
		gXPF.kernelStringSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__cstring");
		gXPF.kernelConstSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__const");
		gXPF.kernelDataConstSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__DATA_CONST", "__const");
		gXPF.kernelDataSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__DATA", "__data");
		gXPF.kernelOSLogSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__TEXT", "__os_log");
		gXPF.kernelBootdataInit = pfsec_init_from_macho(gXPF.kernel, NULL, "__BOOTDATA", "__init");
		gXPF.kernelPrelinkTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__PRELINK_TEXT", "__text");
		gXPF.kernelPLKTextSection = pfsec_init_from_macho(gXPF.kernel, NULL, "__PLK_TEXT_EXEC", "__text");
	}

	if (gXPF.kernelTextSection) pfsec_set_cached(gXPF.kernelTextSection, true);
	if (gXPF.kernelPPLTextSection) pfsec_set_cached(gXPF.kernelPPLTextSection, true);
	if (gXPF.kernelStringSection) pfsec_set_cached(gXPF.kernelStringSection, true);
	if (gXPF.kernelConstSection) pfsec_set_cached(gXPF.kernelConstSection, true);
	if (gXPF.kernelDataConstSection) pfsec_set_cached(gXPF.kernelDataConstSection, true);
	if (gXPF.kernelDataSection) pfsec_set_cached(gXPF.kernelDataSection, true);
	if (gXPF.kernelOSLogSection) pfsec_set_cached(gXPF.kernelOSLogSection, true);
	if (gXPF.kernelBootdataInit) pfsec_set_cached(gXPF.kernelBootdataInit, true);
	if (gXPF.kernelPrelinkTextSection) pfsec_set_cached(gXPF.kernelPrelinkTextSection, true);
	if (gXPF.kernelPLKTextSection) pfsec_set_cached(gXPF.kernelPLKTextSection, true);
	if (gXPF.kernelAMFITextSection) pfsec_set_cached(gXPF.kernelAMFITextSection, true);
	if (gXPF.kernelAMFIStringSection) pfsec_set_cached(gXPF.kernelAMFIStringSection, true);
	if (gXPF.kernelInfoPlistSection) pfsec_set_cached(gXPF.kernelInfoPlistSection, true);

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
		xpf_set_error("Failed to find kernel base");
		return -1;
	}
	if (!gXPF.kernelEntry) {
		xpf_set_error("Failed to find kernel entry point");
		return -1;
	}

	const char *versionSearchString = "Darwin Kernel Version ";
	PFPatternMetric *versionMetric = pfmetric_pattern_init((void *)versionSearchString, NULL, strlen(versionSearchString), sizeof(uint8_t));
	pfmetric_run(gXPF.kernelConstSection, versionMetric, ^(uint64_t vmaddr, bool *stop) {
		int r = pfsec_read_string(gXPF.kernelConstSection, vmaddr, &gXPF.kernelVersionString);
		*stop = true;
	});
	pfmetric_free(versionMetric);

	if (gXPF.kernelInfoPlistSection) {
		const char *infoPlistString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		PFPatternMetric *infoPlistMetric = pfmetric_pattern_init((void *)infoPlistString, NULL, strlen(infoPlistString), sizeof(uint8_t));
		pfmetric_run(gXPF.kernelInfoPlistSection, infoPlistMetric, ^(uint64_t vmaddr, bool *stop) {
			int r = pfsec_read_string(gXPF.kernelInfoPlistSection, vmaddr, &gXPF.kernelInfoPlist);
			*stop = true;
		});
		pfmetric_free(infoPlistMetric);
	}

	if (!gXPF.kernelVersionString) {
		xpf_set_error("Failed to find kernel version");
		return -1;
	}
	else {
		char darwinVersion[100];
		char xnuBuild[100];
		char xnuPlatform[100];
		sscanf(gXPF.kernelVersionString, "Darwin Kernel Version %[^:]: %*[^;]; root:xnu-%[^/]/%s", darwinVersion, xnuBuild, xnuPlatform);
		gXPF.darwinVersion = strdup(darwinVersion);
		gXPF.xnuBuild = strdup(xnuBuild);
		gXPF.xnuPlatform = strdup(xnuPlatform);

		if (gXPF.kernelInfoPlistSection) {
			char osVersion[100];
			const char *DTPlatformVersion = strstr(gXPF.kernelInfoPlist, "<key>DTPlatformVersion</key>");
			sscanf(DTPlatformVersion, "<key>DTPlatformVersion</key>\t<string>%9[^<]</string>", osVersion);
			gXPF.osVersion = strdup(osVersion);
		}
	}

	xpf_ppl_init();
	xpf_non_ppl_init();
	xpf_common_init();
	xpf_bad_recovery_init();

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

uint64_t xpf_item_resolve(const char *name)
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

void xpf_print_all_items(void)
{
	XPFItem *item = gXPF.firstItem;
	while (item) {
		printf("0x%016llx <- %s\n", xpf_item_resolve(item->name), item->name);
		item = item->nextItem;
	}
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

bool xpf_set_is_supported(const char *name)
{
	uint32_t setCount = (sizeof(gSets)/sizeof(XPFSet*));
	for (int i = 0; i < setCount; i++) {
		if (!strcmp(gSets[i]->name, name)) {
			if (gSets[i]->supported()) return true;
		}
	}
	return false;
}

int xpf_offset_dictionary_add_set(xpc_object_t xdict, XPFSet *set)
{
	if (!set->supported()) {
		return -1;
	}

	for (int i = 0; set->metrics[i]; i++) {
		uint64_t resolved = xpf_item_resolve(set->metrics[i]);
		if (resolved) {
			xpc_dictionary_set_uint64(xdict, set->metrics[i], resolved);
		}
		else {
			const char *existingError = xpf_get_error();
			if (existingError) {
				xpf_set_error("Set \"%s\" failed on \"%s\" (%s)", set->name, set->metrics[i], existingError);
			}
			else {
				xpf_set_error("Set \"%s\" failed on \"%s\"", set->name, set->metrics[i]);
			}
			return -1;
		}
	}
	return 0;
}

xpc_object_t xpf_construct_offset_dictionary(const char *sets[])
{
	xpc_object_t offsetDictionary = xpc_dictionary_create_empty();

	if (xpf_offset_dictionary_add_set(offsetDictionary, &gBaseSet) != 0) return NULL;

	uint32_t setCount = (sizeof(gSets)/sizeof(XPFSet*));

	for (int i = 0; sets[i]; i++) {
		for (int j = 0; j < setCount; j++) {
			if (!strcmp(gSets[j]->name, sets[i])) {
				if (!gSets[j]->supported()) continue;
				int r = xpf_offset_dictionary_add_set(offsetDictionary, gSets[j]);
				if (r != 0) {
					xpc_release(offsetDictionary);
					return NULL;
				}
				break;
			}
			else {
				if (j == (setCount-1)) {
					xpf_set_error("Failed to find set \"%s\"", sets[i]);
					xpc_release(offsetDictionary);
					return NULL;
				}
			}
		}
	}

	return offsetDictionary;
}

static char *gXPFError;

void xpf_set_error(const char *error, ...)
{
	char *newError = NULL;
	va_list va;
	va_start(va, error);
	vasprintf(&newError, error, va);
	va_end(va);

	if (gXPFError) {
		free(gXPFError);
	}
	gXPFError = newError;
}

const char *xpf_get_error(void)
{
	return gXPFError;
}

void xpf_stop(void)
{
	if (gXPF.mappedKernel) {
		munmap(gXPF.mappedKernel, gXPF.kernelSize);
	}
	if (gXPF.decompressedKernel) {
		free(gXPF.decompressedKernel);
	}
	if (gXPF.kernelFd >= 0) {
		close(gXPF.kernelFd);
	}

	if (gXPF.kernelTextSection) pfsec_free(gXPF.kernelTextSection);
	if (gXPF.kernelPPLTextSection) pfsec_free(gXPF.kernelPPLTextSection);
	if (gXPF.kernelStringSection) pfsec_free(gXPF.kernelStringSection);
	if (gXPF.kernelConstSection) pfsec_free(gXPF.kernelConstSection);
	if (gXPF.kernelDataConstSection) pfsec_free(gXPF.kernelDataConstSection);
	if (gXPF.kernelDataSection) pfsec_free(gXPF.kernelDataSection);
	if (gXPF.kernelOSLogSection) pfsec_free(gXPF.kernelOSLogSection);
	if (gXPF.kernelAMFITextSection) pfsec_free(gXPF.kernelAMFITextSection);
	if (gXPF.kernelAMFIStringSection) pfsec_free(gXPF.kernelAMFIStringSection);
	if (gXPF.kernelPrelinkTextSection) pfsec_free(gXPF.kernelPrelinkTextSection);
	if (gXPF.kernelBootdataInit) pfsec_free(gXPF.kernelBootdataInit);
	if (gXPF.kernelPLKTextSection) pfsec_free(gXPF.kernelPLKTextSection);
	if (gXPF.kernelInfoPlistSection) pfsec_free(gXPF.kernelInfoPlistSection);
	if (gXPF.kernelContainer) fat_free(gXPF.kernelContainer);

	if (gXPF.kernelVersionString) free(gXPF.kernelVersionString);
	if (gXPF.darwinVersion) free(gXPF.darwinVersion);
	if (gXPF.xnuBuild) free(gXPF.xnuBuild);
	if (gXPF.xnuPlatform) free(gXPF.xnuPlatform);
	if (gXPF.osVersion) free(gXPF.osVersion);
	if (gXPF.kernelInfoPlist) free(gXPF.kernelInfoPlist);

	XPFItem *item = gXPF.firstItem;
	while (item) {
		XPFItem *curItem = item;
		item = item->nextItem;
		free(curItem);
	}
	
	gXPF = (struct s_XPF){ 0 };
}