#include "xpf.h"

uint64_t xpf_non_ppl_pmap_enter_options(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_enter_options_internal");
	__block uint64_t pmap_enter_options_stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		pmap_enter_options_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	
	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_enter_options_stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_enter_options = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_enter_options = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	
	return pmap_enter_options;
}

uint64_t xpf_non_ppl_pmap_remove_options_internal(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_remove_options_internal");
	__block uint64_t pmap_remove_options_internal_stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		pmap_remove_options_internal_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	
	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_remove_options_internal_stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_remove_options_internal = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_remove_options_internal = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	
	return pmap_remove_options_internal;
}

uint64_t xpf_find_non_ppl_pmap_image4_trust_caches(void)
{
	// search pmap_is_trust_cache_loaded
	uint32_t inst[] = {
		0x39400400, // ldrb wN, [xM, #0x1]
		0x39401400, // ldrb wN, [xM, #0x5]
		0x6b00001f, // cmp wN, wM
		0x54000001, // b.ne
		0x39400800, // ldrb wN, [xM, #0x2]
		0x39401800, // ldrb wN, [xM, #0x6]
		0x6b00001f, // cmp wN, wM
		0x54000001, // b.ne
	};
	uint32_t mask[] = {
		0xff40fc00,
		0xff40fc00,
		0xffe0fc1f,
		0xff00001f,
		0xff40fc00,
		0xff40fc00,
		0xffe0fc1f,
		0xff00001f,
	};
	
	PFPatternMetric *metric = pfmetric_pattern_init(&inst, &mask, sizeof(inst), sizeof(uint32_t));
	__block uint64_t found = 0;
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		found = vmaddr;
		*stop = true;
	});
	pfmetric_free(metric);
	
	if(found) {
		uint32_t adrpInst = 0, adrpInstAny = 0;
		arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_ANY, &adrpInst, &adrpInstAny);
		uint64_t adrpAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, found, 20, adrpInst, adrpInstAny);
		if (adrpAddr) {
			return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr + 4);
		}
	}
	
	return 0;
}

void xpf_non_ppl_init(void)
{
	if (!gXPF.kernelIsArm64e) {
		xpf_item_register("kernelSymbol.pmap_enter_options", xpf_non_ppl_pmap_enter_options, NULL);
		xpf_item_register("kernelSymbol.pmap_remove_options_internal", xpf_non_ppl_pmap_remove_options_internal, NULL);
		
		if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
			// iOS >=16
			
		}
		else {
			// iOS <=15
			xpf_item_register("kernelSymbol.non_ppl_pmap_image4_trust_caches", xpf_find_non_ppl_pmap_image4_trust_caches, NULL);
		}
	}
}
