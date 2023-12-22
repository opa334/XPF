#include <time.h>
#include <sys/mman.h>
#include "../xpf.h"

int main(int argc, char *argv[]) {
    if (argc == 1) {

    }
    else {
        if (xpf_start_with_kernel_path(argv[1]) == 0) {
            printf("Started KPF with %s\n", argv[1]);
            clock_t t = clock();

            printf("ppl_handler_table: 0x%llx\n", xpf_resolve_item("ppl_handler_table"));
            printf("sysent: 0x%llx\n", xpf_resolve_item("sysent"));
            printf("pmap_enter_options_internal: 0x%llx\n", xpf_resolve_item("pmap_enter_options_internal"));

            t = clock() - t;
            double time_taken = ((double)t)/CLOCKS_PER_SEC;
            printf("KPF finished in %lf seconds\n", time_taken);
            xpf_stop();
        }
    }
    return 0;
}