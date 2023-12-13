#include "choma/FAT.h"
#include "choma/MachO.h"
#include "choma/PatchFinder.h"
#include "choma/Util.h"
#include "choma/arm64.h"
#include <mach/machine.h>
#include <sys/_types/_null.h>
#include "kpf.h"

struct s_gKPF {
	FAT *kernelContainer;
	MachO *kernel;
	bool kernelIsFileset;

	PFSection *kernelTextSection;
	PFSection *kernelStringSection;

	uint64_t sysent;
	uint64_t ppl_handler_trampoline;
} gKpf;

typedef struct s_KPFField {
	const char *name;
	uint64_t (*find)(void);
} KPFField;

int kpf_start_with_kernel_path(const char *kernelPath)
{
	FAT *candidate = fat_init_from_path(kernelPath);
	if (!candidate) return -1;

	MachO *machoCandidate = NULL;
	machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
	if (!machoCandidate) {
		machoCandidate = fat_find_slice(candidate, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
	}
	if (!machoCandidate) return -1;

	gKpf.kernelContainer = candidate;
	gKpf.kernel = machoCandidate;
	gKpf.kernelIsFileset = macho_get_filetype(gKpf.kernel) == MH_FILESET;

	if (gKpf.kernelIsFileset) {
		gKpf.kernelTextSection = pf_section_init_from_macho(gKpf.kernel, "com.apple.kernel", "__TEXT_EXEC", "__text");
		gKpf.kernelStringSection = pf_section_init_from_macho(gKpf.kernel, "com.apple.kernel", "__TEXT", "__cstring");
	}
	else {
		// TODO
	}

	return 0;
}

void kpf_stop(void)
{
	if (gKpf.kernelStringSection) {
		pf_section_free(gKpf.kernelStringSection);
	}
	if (gKpf.kernelTextSection) {
		pf_section_free(gKpf.kernelTextSection);
	}
	if (gKpf.kernelContainer) {
		fat_free(gKpf.kernelContainer);
	}
}

uint64_t kpf_find_sysent(void)
{
	return 0;
}

uint64_t kpf_find_ppl_enter(void)
{
	uint32_t bAny = 0, bAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE, &bAny, &bAnyMask);
	uint32_t movX15Any = 0xd280000f, movX15AnyMask = 0xffe0001f;

	uint32_t pplCallerInst[] = {
		movX15Any,
		bAny,
		movX15Any,
		bAny,
	};
	uint32_t pplCallerMask[] = {
		movX15AnyMask,
		bAnyMask,
		movX15AnyMask,
		bAnyMask,
	};

	__block uint64_t ppl_enter = 0;
	PFBytePatternMetric *metric = pf_create_byte_pattern_metric(pplCallerInst,pplCallerMask,sizeof(pplCallerInst), BYTE_PATTERN_ALIGN_32_BIT);
	pf_section_run_metric(gKpf.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		arm64_dec_b_l(pf_section_read32(gKpf.kernelTextSection, vmaddr+4), vmaddr+4, &ppl_enter, NULL);
		*stop = true;
	});
	return ppl_enter;
}

uint64_t kpf_find_ppl_bootstrap_dispatch(void)
{
	uint64_t ppl_enter = kpf_find_ppl_enter();

	uint32_t cbzAny = 0, cbzAnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_ANY, OPT_UINT64_NONE, &cbzAny, &cbzAnyMask);

	uint64_t cbzPPLDispatch = pf_section_find_next_inst(gKpf.kernelTextSection, ppl_enter, 30, cbzAny, cbzAnyMask);
	uint64_t ppl_bootstrap_dispatch = 0;
	arm64_dec_cb_n_z(pf_section_read32(gKpf.kernelTextSection, cbzPPLDispatch), cbzPPLDispatch, NULL, NULL, &ppl_bootstrap_dispatch);
	
	return ppl_bootstrap_dispatch;
}

uint64_t kpf_find_ppl_handler_routine(void)
{
	uint64_t ppl_bootstrap_dispatch = kpf_find_ppl_bootstrap_dispatch();

	uint32_t addAny = 0, addAnyMask = 0;
	arm64_gen_add_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &addAny, &addAnyMask);
	
	uint64_t addAddr = pf_section_find_next_inst(gKpf.kernelTextSection, ppl_bootstrap_dispatch, 30, addAny, addAnyMask);
	uint64_t adrpAddr = addAddr - 4;

	uint32_t adrpInst = pf_section_read32(gKpf.kernelTextSection, adrpAddr);
	uint32_t addInst = pf_section_read32(gKpf.kernelTextSection, addAddr);

	uint64_t adrpTarget = 0;
	if (arm64_dec_adr_p(adrpInst, adrpAddr, &adrpTarget, NULL, NULL) != 0) {
		printf("ppl_handler_routine: Failed decoding adrp at 0x%llx (0x%x)\n", adrpAddr, adrpInst);
		return 0;
	}
	
	uint16_t addImm = 0;
	if (arm64_dec_add_imm(addInst, NULL, NULL, &addImm) != 0) {
		printf("ppl_handler_routine: Failed decoding add at 0x%llx (0x%x)\n", addAddr, addInst);
		return 0;
	}

	return adrpTarget + addImm;
}

const KPFField availableFields[] = {
	{ "sysent", kpf_find_sysent },
	{ "ppl_handler_table", kpf_find_ppl_handler_routine },
};

uint64_t kpf_get_field(const char *field)
{
	for (int i = 0; i < (sizeof(availableFields) / sizeof(KPFField)); i++) {
		if (!strcmp(availableFields[i].name, field)) {
			return availableFields[i].find();
		}
	}
	return 0;
}