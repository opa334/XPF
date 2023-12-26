#include <stdint.h>

#include <choma/FAT.h>
#include <choma/Util.h>
#include <choma/PatchFinder.h>
#include <choma/arm64.h>

int xpf_start_with_kernel_path(const char *kernelPath);
void xpf_item_register(const char *name, void *finder, void *ctx);
uint64_t xpf_resolve_item(const char *name);
uint64_t xpfsec_read_ptr(PFSection *section, uint64_t vmaddr);
void xpf_stop(void);

typedef struct s_XPFItem {
	struct s_XPFItem *nextItem;
	const char *name;
	uint64_t (*finder)(void *);
	void *ctx;
	bool cached;
	uint64_t cache;
} XPFItem;

typedef struct s_XPF {
	FAT *kernelContainer;
	MachO *kernel;
	bool kernelIsFileset;

	uint64_t kernelBase;
	uint64_t kernelEntry;

	PFSection *kernelTextSection;
	PFSection *kernelPPLTextSection;
	PFSection *kernelStringSection;
	PFSection *kernelDataConstSection;

	XPFItem *firstItem;
} XPF;
extern XPF gXPF;
