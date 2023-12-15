#import "ppl.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

uint64_t xpf_find_ppl_enter(void)
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
	pf_section_run_metric(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		arm64_dec_b_l(pf_section_read32(gXPF.kernelTextSection, vmaddr+4), vmaddr+4, &ppl_enter, NULL);
		*stop = true;
	});
	return ppl_enter;
}

uint64_t xpf_find_ppl_bootstrap_dispatch(void)
{
	uint64_t ppl_enter = xpf_resolve_item("ppl_enter");

	uint32_t cbzAny = 0, cbzAnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_ANY, OPT_UINT64_NONE, &cbzAny, &cbzAnyMask);

	uint64_t cbzPPLDispatch = pf_section_find_next_inst(gXPF.kernelTextSection, ppl_enter, 30, cbzAny, cbzAnyMask);
	uint64_t ppl_bootstrap_dispatch = 0;
	arm64_dec_cb_n_z(pf_section_read32(gXPF.kernelTextSection, cbzPPLDispatch), cbzPPLDispatch, NULL, NULL, &ppl_bootstrap_dispatch);

	return ppl_bootstrap_dispatch;
}

uint64_t xpf_find_ppl_handler_table(void)
{
	uint64_t ppl_bootstrap_dispatch = xpf_resolve_item("ppl_bootstrap_dispatch");

	uint32_t addAny = 0, addAnyMask = 0;
	arm64_gen_add_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &addAny, &addAnyMask);

	uint64_t addAddr = pf_section_find_next_inst(gXPF.kernelTextSection, ppl_bootstrap_dispatch, 30, addAny, addAnyMask);
	uint64_t adrpAddr = addAddr - 4;

	uint32_t adrpInst = pf_section_read32(gXPF.kernelTextSection, adrpAddr);
	uint32_t addInst = pf_section_read32(gXPF.kernelTextSection, addAddr);

	uint64_t adrpTarget = 0;
	if (arm64_dec_adr_p(adrpInst, adrpAddr, &adrpTarget, NULL, NULL) != 0) {
		printf("ppl_handler_table: Failed decoding adrp at 0x%llx (0x%x)\n", adrpAddr, adrpInst);
		return 0;
	}

	uint16_t addImm = 0;
	if (arm64_dec_add_imm(addInst, NULL, NULL, &addImm) != 0) {
		printf("ppl_handler_table: Failed decoding add at 0x%llx (0x%x)\n", addAddr, addInst);
		return 0;
	}

	return adrpTarget + addImm;
}

void xpf_ppl_init(void)
{
	xpf_item_register("ppl_enter", xpf_find_ppl_enter);
	xpf_item_register("ppl_bootstrap_dispatch", xpf_find_ppl_bootstrap_dispatch);
	xpf_item_register("ppl_handler_table", xpf_find_ppl_handler_table);
}