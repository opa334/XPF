#import "ppl.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

uint64_t xpf_find_ppl_dispatch_section(void)
{
	uint32_t bAny = 0, bAnyMask = 0, movX15Any = 0, movX15AnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE, &bAny, &bAnyMask);
	arm64_gen_mov_imm('z', ARM64_REG_X(15), OPT_UINT64_NONE, OPT_UINT64(0), &movX15Any, &movX15AnyMask);

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

	__block uint64_t ppl_dispatch_section = 0;
	PFPatternMetric *metric = pfmetric_pattern_init(pplCallerInst,pplCallerMask,sizeof(pplCallerInst), BYTE_PATTERN_ALIGN_32_BIT);
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		ppl_dispatch_section = vmaddr;
		*stop = true;
	});
	return ppl_dispatch_section;
}

uint64_t xpf_find_ppl_enter(void)
{
	uint64_t ppl_dispatch_section = xpf_resolve_item("ppl_dispatch_section");
	__block uint64_t ppl_enter = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, ppl_dispatch_section+4), ppl_dispatch_section+4, &ppl_enter, NULL);
	return ppl_enter;
}

uint64_t xpf_find_ppl_bootstrap_dispatch(void)
{
	uint64_t ppl_enter = xpf_resolve_item("ppl_enter");

	uint32_t cbzAny = 0, cbzAnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_ANY, OPT_UINT64_NONE, &cbzAny, &cbzAnyMask);

	uint64_t cbzPPLDispatch = pfsec_find_next_inst(gXPF.kernelTextSection, ppl_enter, 30, cbzAny, cbzAnyMask);
	uint64_t ppl_bootstrap_dispatch = 0;
	arm64_dec_cb_n_z(pfsec_read32(gXPF.kernelTextSection, cbzPPLDispatch), cbzPPLDispatch, NULL, NULL, &ppl_bootstrap_dispatch);

	return ppl_bootstrap_dispatch;
}

uint64_t xpf_find_ppl_handler_table(void)
{
	uint64_t ppl_bootstrap_dispatch = xpf_resolve_item("ppl_bootstrap_dispatch");

	uint32_t addAny = 0, addAnyMask = 0;
	arm64_gen_add_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &addAny, &addAnyMask);

	uint64_t addAddr = pfsec_find_next_inst(gXPF.kernelTextSection, ppl_bootstrap_dispatch, 30, addAny, addAnyMask);
	uint64_t adrpAddr = addAddr - 4;

	uint32_t adrpInst = pfsec_read32(gXPF.kernelTextSection, adrpAddr);
	uint32_t addInst = pfsec_read32(gXPF.kernelTextSection, addAddr);

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

uint64_t xpf_find_ppl_routine(uint32_t idx)
{
	uint64_t ppl_handler_table = xpf_resolve_item("ppl_handler_table");
	return xpfsec_read_ptr(gXPF.kernelDataConstSection, ppl_handler_table + (sizeof(uint64_t) * idx));
}

uint64_t xpf_find_ppl_dispatch_func(uint32_t idx)
{
	uint64_t ppl_dispatch_section = xpf_resolve_item("ppl_dispatch_section");

	uint32_t movToFind = 0, movMaskToFind = 0;
	arm64_gen_mov_imm('z', ARM64_REG_X(15), OPT_UINT64(idx), OPT_UINT64(0), &movToFind, &movMaskToFind);

	return pfsec_find_next_inst(gXPF.kernelTextSection, ppl_dispatch_section, 1000, movToFind, movMaskToFind);
}

uint64_t xpf_find_pmap_image4_trust_caches(void)
{
	uint64_t pmap_lookup_in_loaded_trust_caches_internal = xpf_resolve_item("pmap_lookup_in_loaded_trust_caches_internal");

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_lit(ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);
	uint64_t ldrAddr = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_lookup_in_loaded_trust_caches_internal, 20, ldrAny, ldrAnyMask);

	int64_t ldrTarget = 0;
	arm64_dec_ldr_lit(pfsec_read32(gXPF.kernelPPLTextSection, ldrAddr), NULL, &ldrTarget);
	return ldrAddr + ldrTarget;
}

void xpf_ppl_init(void)
{
	xpf_item_register("ppl_enter", xpf_find_ppl_enter, NULL);
	xpf_item_register("ppl_bootstrap_dispatch", xpf_find_ppl_bootstrap_dispatch, NULL);
	xpf_item_register("ppl_dispatch_section", xpf_find_ppl_dispatch_section, NULL);
	xpf_item_register("ppl_handler_table", xpf_find_ppl_handler_table, NULL);
	xpf_item_register("pmap_enter_options_internal", xpf_find_ppl_routine, (void *)(uint32_t)10);
	xpf_item_register("pmap_enter_options_ppl", xpf_find_ppl_dispatch_func, (void *)(uint32_t)10);
	xpf_item_register("pmap_lookup_in_loaded_trust_caches_internal", xpf_find_ppl_routine, (void *)(uint32_t)41);
	xpf_item_register("pmap_image4_trust_caches", xpf_find_pmap_image4_trust_caches, NULL);

}