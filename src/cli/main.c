#include <time.h>
#include <sys/mman.h>
#include "../xpf.h"

int main(int argc, char *argv[]) {
    if (argc == 1) {

    }
    else {
        int err = xpf_start_with_kernel_path(argv[1]);
        if (err == 0) {
            printf("Starting XPF with %s\n", argv[1]);
            clock_t t = clock();

            printf("Kernel base: 0x%llx\n", gXPF.kernelBase);
        	printf("Kernel entry: 0x%llx\n", gXPF.kernelEntry);

            printf("start_first_cpu: 0x%llx\n", xpf_resolve_item("start_first_cpu"));
            printf("cpu_ttep: 0x%llx\n", xpf_resolve_item("cpu_ttep"));
            printf("kernel_el: 0x%llx\n", xpf_resolve_item("kernel_el"));
            printf("kalloc_data_external: 0x%llx\n", xpf_resolve_item("kalloc_data_external"));
            printf("kfree_data_external: 0x%llx\n", xpf_resolve_item("kfree_data_external"));
            printf("allproc: 0x%llx\n", xpf_resolve_item("allproc"));

            printf("hw_lck_ticket_reserve_orig_allow_invalid_signed: 0x%llx\n", xpf_resolve_item("hw_lck_ticket_reserve_orig_allow_invalid_signed"));
            printf("hw_lck_ticket_reserve_orig_allow_invalid: 0x%llx\n", xpf_resolve_item("hw_lck_ticket_reserve_orig_allow_invalid"));
            printf("br_x22_gadget: 0x%llx\n", xpf_resolve_item("br_x22_gadget"));
            printf("exception_return: 0x%llx\n", xpf_resolve_item("exception_return"));
            printf("exception_return_after_check: 0x%llx\n", xpf_resolve_item("exception_return_after_check"));
            printf("exception_return_after_check_no_restore: 0x%llx\n", xpf_resolve_item("exception_return_after_check_no_restore"));
            printf("ldp_x0_x1_x8_gadget: 0x%llx\n", xpf_resolve_item("ldp_x0_x1_x8_gadget"));
            printf("str_x8_x9_gadget: 0x%llx\n", xpf_resolve_item("str_x8_x9_gadget"));
            printf("str_x0_x19_ldr_x20_gadget: 0x%llx\n", xpf_resolve_item("str_x0_x19_ldr_x20_gadget"));
            printf("pacda_gadget: 0x%llx\n", xpf_resolve_item("pacda_gadget"));
            printf("vm_page_array_beginning_addr: 0x%llx\n", xpf_resolve_item("vm_page_array_beginning_addr"));
            printf("vm_page_array_ending_addr: 0x%llx\n", xpf_resolve_item("vm_page_array_ending_addr"));
            printf("vm_first_phys_ppnum: 0x%llx\n", xpf_resolve_item("vm_first_phys_ppnum"));

            printf("ppl_handler_table: 0x%llx\n", xpf_resolve_item("ppl_handler_table"));
            //printf("sysent: 0x%llx\n", xpf_resolve_item("sysent"));
            printf("pmap_enter_options_internal: 0x%llx\n", xpf_resolve_item("pmap_enter_options_internal"));
            printf("pmap_enter_options_ppl: 0x%llx\n", xpf_resolve_item("pmap_enter_options_ppl"));
            printf("pmap_lookup_in_loaded_trust_caches_internal: 0x%llx\n", xpf_resolve_item("pmap_lookup_in_loaded_trust_caches_internal"));
            printf("pmap_image4_trust_caches: 0x%llx\n", xpf_resolve_item("pmap_image4_trust_caches"));
            
            printf("arm_vm_init: 0x%llx\n", xpf_resolve_item("arm_vm_init"));
            printf("phystokv: 0x%llx\n", xpf_resolve_item("phystokv"));
            printf("gVirtBase: 0x%llx\n", xpf_resolve_item("gVirtBase"));
            printf("gPhysBase: 0x%llx\n", xpf_resolve_item("gPhysBase"));
            printf("gPhysSize: 0x%llx\n", xpf_resolve_item("gPhysSize"));
            printf("ptov_table: 0x%llx\n", xpf_resolve_item("ptov_table"));

            printf("ITK_SPACE: 0x%llx\n", xpf_resolve_item("ITK_SPACE"));

            t = clock() - t;
            double time_taken = ((double)t)/CLOCKS_PER_SEC;
            printf("KPF finished in %lf seconds\n", time_taken);
            xpf_stop();
        }
        else {
            printf("Failed to start XPF: %d\n", err);
        }
    }
    return 0;
}