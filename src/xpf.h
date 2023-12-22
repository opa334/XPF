#include <stdint.h>

#include <choma/FAT.h>
#include <choma/PatchFinder.h>

int xpf_start_with_kernel_path(const char *kernelPath);
void xpf_item_register(const char *name, void *finder, void *ctx);
uint64_t xpf_resolve_item(const char *name);
uint64_t xpf_section_read_ptr(PFSection *section, uint64_t vmaddr);
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

	PFSection *kernelTextSection;
	PFSection *kernelStringSection;
	PFSection *kernelDataConstSection;

	XPFItem *firstItem;
} XPF;
extern XPF gXPF;
