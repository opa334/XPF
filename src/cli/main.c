#include "choma/FAT.h"
#include <choma/CSBlob.h>
#include <choma/Host.h>
#include <choma/BufferedStream.h>
#include <choma/PatchFinder.h>
#include <choma/PatchFinder_arm64.h>
#include <choma/arm64.h>

#include <time.h>
#include <sys/mman.h>
#include "../kpf.h"



int main(int argc, char *argv[]) {
    if (argc == 1) {

    }
    else {
        if (kpf_start_with_kernel_path(argv[1]) == 0) {
            printf("Started KPF with %s\n", argv[1]);
            clock_t t = clock();

            printf("ppl_handler_table: 0x%llx\n", kpf_get_field("ppl_handler_table"));
            printf("sysent: 0x%llx\n", kpf_get_field("sysent"));

            t = clock() - t;
            double time_taken = ((double)t)/CLOCKS_PER_SEC;
            printf("KPF finished in %lf seconds\n", time_taken);
        }
    }
    return 0;
}