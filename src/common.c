#include "xpf.h"

uint64_t xpf_find_arm_vm_init(void)
{
	PFStringMetric *contiguousHintMetric = pfmetric_string_init("use_contiguous_hint");
	__block uint64_t contiguousHintAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, contiguousHintMetric, ^(uint64_t vmaddr, bool *stop) {
		contiguousHintAddr = vmaddr;
		*stop = true;
	});

	__block uint64_t arm_init_mid = 0;
	PFXrefMetric *contiguousHintXrefMetric = pfmetric_xref_init(contiguousHintAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, contiguousHintXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		arm_init_mid = vmaddr;
		*stop = true;
	});

	return pfsec_find_function_start(gXPF.kernelTextSection, arm_init_mid);
}

uint64_t xpf_find_arm_vm_init_reference(uint32_t n)
{
	uint64_t arm_vm_init = xpf_resolve_item("arm_vm_init");

	uint32_t strAny = 0, strAnyMask = 0;
	arm64_gen_str_imm(0, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &strAny, &strAnyMask);

	uint64_t toCheck = arm_vm_init;
	uint64_t strAddr = 0;
	for (int i = 0; i < n; i++) {
		strAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 20, strAny, strAnyMask);
		toCheck = strAddr + 4;
	}

	arm64_register addrReg;
	uint64_t strImm = 0;
	arm64_dec_str_imm(pfsec_read32(gXPF.kernelTextSection, strAddr), NULL, &addrReg, &strImm, NULL);

	uint32_t adrpTemplate = 0, adrpTemplateMask = 0;
	arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, addrReg, &adrpTemplate, &adrpTemplateMask);

	uint64_t adrpAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, strAddr, 20, adrpTemplate, adrpTemplateMask);
	uint64_t adrpTarget = 0;
	arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);
	
	return adrpTarget + strImm;
}

uint64_t xpf_find_phystokv(void)
{
	uint64_t arm_vm_init = xpf_resolve_item("arm_vm_init");

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);

	uint64_t blPhystokvAddr = pfsec_find_next_inst(gXPF.kernelTextSection, arm_vm_init, 100, blAny, blAnyMask);
	uint64_t phystokv = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, blPhystokvAddr), blPhystokvAddr, &phystokv, NULL);
	return phystokv;
}

/*uint64_t xpf_find_gVirtSize(void)
{
	return 0;
}*/

uint64_t xpf_find_ptov_table(void)
{
	uint64_t phystokv = xpf_resolve_item("phystokv");

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);

	// Second ldr in phytokv references ptov_table
	uint64_t toCheck = phystokv;
	uint64_t ldrAddr = 0;
	for (int i = 0; i < 2; i++) {
		ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 20, ldrAny, ldrAnyMask);
		toCheck = ldrAddr + 4;
	}

	uint64_t ldrImm = 0;
	arm64_dec_ldr_imm(pfsec_read32(gXPF.kernelTextSection, ldrAddr), NULL, NULL, &ldrImm, NULL);
	uint64_t adrpAddr = ldrAddr - 4;
	uint64_t adrpTarget = 0;
	arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);
	return adrpTarget + ldrImm;
}

uint64_t xpf_find_start_first_cpu(void)
{
	uint64_t start_first_cpu = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, gXPF.kernelEntry), gXPF.kernelEntry, &start_first_cpu, NULL);
	return start_first_cpu;
}

uint64_t xpf_find_cpu_ttep(void)
{
	uint64_t start_first_cpu = xpf_resolve_item("start_first_cpu");

	uint32_t cbzX21Any = 0, cbzX21AnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_X(21), OPT_UINT64_NONE, &cbzX21Any, &cbzX21AnyMask);

	uint64_t cpu_ttep_pre = pfsec_find_next_inst(gXPF.kernelTextSection, start_first_cpu, 0, cbzX21Any, cbzX21AnyMask);

	uint64_t adrpAddr = cpu_ttep_pre + 4;
	uint64_t addAddr = cpu_ttep_pre + 8;

	uint64_t adrpTarget = 0;
	arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);

	uint16_t addImm = 0;
	arm64_dec_add_imm(addAddr, NULL, NULL, &addImm);

	return adrpTarget + addImm;
}

uint64_t xpf_find_kernel_el(void)
{
	uint64_t start_first_cpu = xpf_resolve_item("start_first_cpu");

	uint32_t inst = pfsec_read32(gXPF.kernelTextSection, start_first_cpu + 16);
	if (inst == 0xD5384240 /* msr x0, CurrentEL */) {
		return 2;
	}

	return 1;
}

uint64_t xpf_find_kalloc_data_external(void)
{
	PFStringMetric *amfiErrorMetric = pfmetric_string_init("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.\n");
	__block uint64_t amfiErrorAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, amfiErrorMetric, ^(uint64_t vmaddr, bool *stop) {
		amfiErrorAddr = vmaddr;
		*stop = true;
	});

	__block uint64_t amfiFatalErrorMid = 0;
	PFXrefMetric *amfiErrorXrefMetric = pfmetric_xref_init(amfiErrorAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, amfiErrorXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		amfiFatalErrorMid = vmaddr;
		*stop = true;
	});

	uint64_t amfiFatalError = pfsec_find_function_start(gXPF.kernelTextSection, amfiFatalErrorMid);

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);
	uint64_t kallocDataExternalBlAddr = pfsec_find_next_inst(gXPF.kernelTextSection, amfiFatalError, 20, blAny, blAnyMask);
	uint32_t kallocDataExternalBl = pfsec_read32(gXPF.kernelTextSection, kallocDataExternalBlAddr);

	uint64_t kallocDataExternal = 0;
	arm64_dec_b_l(kallocDataExternalBl, kallocDataExternalBlAddr, &kallocDataExternal, NULL);
	return kallocDataExternal;
}

uint64_t xpf_find_kfree_data_external(void)
{
	PFStringMetric *amfiErrorMetric = pfmetric_string_init("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.\n");
	__block uint64_t amfiErrorAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, amfiErrorMetric, ^(uint64_t vmaddr, bool *stop) {
		amfiErrorAddr = vmaddr;
		*stop = true;
	});

	__block uint64_t amfiFatalErrorMid = 0;
	PFXrefMetric *amfiErrorXrefMetric = pfmetric_xref_init(amfiErrorAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, amfiErrorXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		amfiFatalErrorMid = vmaddr;
		*stop = true;
	});

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);

	// Second bl after ref is call to kfree_data_external
	uint64_t toCheck = amfiFatalErrorMid;
	uint64_t blAddr = 0;
	for (int i = 0; i < 2; i++) {
		blAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 20, blAny, blAnyMask);
		toCheck = blAddr + 4;
	}

	uint64_t kfree_data_external = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, blAddr), blAddr, &kfree_data_external, NULL);
	return kfree_data_external;
}

uint64_t xpf_find_allproc(void)
{
	PFStringMetric *shutdownwaitMetric = pfmetric_string_init("shutdownwait");
	__block uint64_t shutdownwaitString = 0;
	pfmetric_run(gXPF.kernelStringSection, shutdownwaitMetric, ^(uint64_t vmaddr, bool *stop) {
		shutdownwaitString = vmaddr;
		*stop = true;
	});

	PFXrefMetric *shutdownwaitXrefMetric = pfmetric_xref_init(shutdownwaitString, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t shutdownwaitXref = 0;
	pfmetric_run(gXPF.kernelTextSection, shutdownwaitXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		shutdownwaitXref = vmaddr;
		*stop = true;
	});

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);

	uint64_t ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, shutdownwaitXref, 20, ldrAny, ldrAnyMask);
	uint64_t adrpAddr = ldrAddr - 4;

	uint64_t adrpTarget = 0;
	arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);

	uint64_t ldrImm = 0;
	arm64_dec_ldr_imm(pfsec_read32(gXPF.kernelTextSection, ldrAddr), NULL, NULL, &ldrImm, NULL);

	return adrpTarget + ldrImm;
}

void xpf_common_init(void)
{
	xpf_item_register("start_first_cpu", xpf_find_start_first_cpu, NULL);
	xpf_item_register("cpu_ttep", xpf_find_cpu_ttep, NULL);
	xpf_item_register("kernel_el", xpf_find_kernel_el, NULL);
	xpf_item_register("kalloc_data_external", xpf_find_kalloc_data_external, NULL);
	xpf_item_register("kfree_data_external", xpf_find_kfree_data_external, NULL);
	xpf_item_register("allproc", xpf_find_allproc, NULL);

	xpf_item_register("arm_vm_init", xpf_find_arm_vm_init, NULL);
	xpf_item_register("phystokv", xpf_find_phystokv, NULL);
	
	xpf_item_register("gVirtBase", xpf_find_arm_vm_init_reference, (void*)(uint32_t)1);
	//xpf_item_register("gVirtSize", xpf_find_gVirtSize, NULL);
	xpf_item_register("gPhysBase", xpf_find_arm_vm_init_reference, (void*)(uint32_t)2);
	xpf_item_register("gPhysSize", xpf_find_arm_vm_init_reference, (void*)(uint32_t)5);
	xpf_item_register("ptov_table", xpf_find_ptov_table, NULL);
}