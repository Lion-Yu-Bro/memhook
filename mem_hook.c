#define _GNU_SOURCE // enable extension for RTLD_NEXT
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdatomic.h>

// enable for implicit memory hook
#define EN_HOOK_IMPLICIT_ALLOC 0 // usually ignore implicit memory
// enable for explicit memory hook
#define EN_HOOK_EXPLICIT_ALLOC 1

// log enable for bad pointer (output logs in realloc, free...)
#define EN_LOG_BADPTR 1
// log enable for each memory allocation and deallocation
#define EN_LOG_MEMCNT 1

#if EN_LOG_BADPTR
#define MEMHOOK_LOG_BADPTR(f,p) ({ \
    write(STDOUT_FILENO, f, strlen(f)); \
    write(STDOUT_FILENO, "(): invalid pointer 0x", 22); \
    char buf[64]; int n = memhook_printx((uintptr_t)p, buf);\
    write(STDOUT_FILENO, buf, n); \
    write(STDOUT_FILENO, "\n", 1); \
})
#else
#define MEMHOOK_LOG_BADPTR(f,p)
#endif
#if EN_LOG_MEMCNT
#define MEMHOOK_LOG_MEMCNT(f,d) ({ \
    write(STDOUT_FILENO, f, strlen(f)); \
    write(STDOUT_FILENO, "(): ", 4); \
    char buf[64]; int n = memhook_printd(d, buf);\
    write(STDOUT_FILENO, buf, n); \
    write(STDOUT_FILENO, " bytes\n", 7); });
#else
#define MEMHOOK_LOG_MEMCNT(f,d)
#endif

typedef void  (*MEMHOOK_cb     )(const char *hook_name, ssize_t delta);
typedef void* (*MEMHOOK_malloc )(size_t size);
typedef void* (*MEMHOOK_calloc )(size_t nmemb, size_t size);
typedef void* (*MEMHOOK_realloc)(void *ptr, size_t size);
typedef int   (*MEMHOOK_posix_memalign)(void **memptr, size_t alignment, size_t size);
typedef void* (*MEMHOOK_aligned_alloc )(size_t alignment, size_t size);
typedef void* (*MEMHOOK_memalign)(size_t boundary, size_t size);
typedef void  (*MEMHOOK_free    )(void *ptr);
typedef void* (*MEMHOOK_valloc  )(size_t size);
typedef void* (*MEMHOOK_pvalloc )(size_t size);
#if EN_HOOK_IMPLICIT_ALLOC
typedef void* (*MEMHOOK_mmap  )(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef void* (*MEMHOOK_mmap64)(void *addr, size_t length, int prot, int flags, int fd, off64_t offset);
typedef void* (*MEMHOOK_mremap)(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
typedef int   (*MEMHOOK_munmap)(void *addr, size_t length);
#ifndef __GLIBC__
typedef void* (*MEMHOOK_brk)(void*, size_t, size_t);
typedef void* (*MEMHOOK_sbrk)(void*, size_t, size_t);
#endif
#endif

static struct memhook_ctx
{
    size_t mem_total;
    MEMHOOK_cb    callback;
    MEMHOOK_malloc  malloc;
    MEMHOOK_calloc  calloc;
    MEMHOOK_realloc realloc;
    MEMHOOK_memalign       memalign;
    MEMHOOK_posix_memalign posix_memalign;
    MEMHOOK_aligned_alloc  aligned_alloc;
    MEMHOOK_valloc  valloc;
    MEMHOOK_pvalloc pvalloc;
    MEMHOOK_free    free;
#if EN_HOOK_IMPLICIT_ALLOC
    MEMHOOK_mmap   mmap;
    MEMHOOK_mmap64 mmap64;
    MEMHOOK_mremap mremap;
    MEMHOOK_munmap munmap;
#ifndef __GLIBC__
    MEMHOOK_brk   brk;
    MEMHOOK_sbrk sbrk;
#endif
#endif
} memhook;

#define HT_BITS     12
#define HT_SIZE     (1u << HT_BITS)
#define HASH(p)     (((uintptr_t)(p) >> 3) & (HT_SIZE - 1))

typedef struct Node {
    void        *ptr;
    size_t       sz;
    struct Node *next;
} Node;

static _Atomic(Node *) htab[HT_SIZE];

static inline Node* ht_find(void *p, Node **prev)
{
    unsigned idx = HASH(p);
    if (prev) *prev = NULL;
    Node *cur = atomic_load_explicit(&htab[idx], memory_order_relaxed);
    while (cur) {
        if (cur->ptr == p) return cur;
        if (prev) *prev = cur;
        cur = cur->next;
    }
    return NULL;
}

static inline void ht_insert(void *p, size_t sz)
{
    Node *n = memhook.malloc(sizeof(Node));
    if (!n) return;
    n->ptr = p;
    n->sz  = sz;

    unsigned idx = HASH(p);
    Node *head;
    do {
        head = atomic_load_explicit(&htab[idx], memory_order_relaxed);
        n->next = head;
    } while (!atomic_compare_exchange_weak(&htab[idx], &head, n));
}

// NULL 'prev' indicate 'cur' is the first Node
static inline void ht_erase(Node *prev, Node *cur)
{
    if (!cur) return;
    unsigned idx = HASH(cur->ptr);
    Node *next = cur->next, *expected;
    if (!prev) {
        do {
            expected = cur;
        } while (!atomic_compare_exchange_weak(&htab[idx], &expected, next));
    } else {
        prev->next = next;
    }
    memhook.free(cur);
}

static int memhook_printd(long d, char *buf)
{
    int i = 0, j = 0, k = 0;
    if (d < 0) { d = -d; k = 1;}
    do {
        buf[i++] = '0' + (d % 10);
        d /= 10;
    } while (d);
    buf[i++] = k ? '-' : '+';
    k = i-1;
    while (k > j) {
        int swap = buf[j];
        buf[j] = buf[k];
        buf[k] = swap;
        k--, j++;
    }
    return i;
}

static int memhook_printx(unsigned x, char *buf)
{
    const char *hex = "0123456789abcdef";
    int i = 0, j = 0, k;
    do {
        buf[i++] = hex[(x & 0xf)];
        x >>= 4;
    } while (x);
    k = i-1;
    while (k > j) {
        int swap = buf[j];
        buf[j] = buf[k];
        buf[k] = swap;
        k--, j++;
    }
    return i;
}

static void memhook_cb(const char *hook_name, ssize_t delta)
{
    // forbid use of any allocator/deallocator function (including 'printf'), otherwise will result in infinite recursion.
    MEMHOOK_LOG_MEMCNT(hook_name, delta);
    return;
}

__attribute__((constructor)) void memhook_init(void)
{
    memhook.mem_total = 0;
    memhook.callback  = memhook_cb;
    memhook.malloc  = dlsym(RTLD_NEXT, "malloc");
    memhook.calloc  = dlsym(RTLD_NEXT, "calloc");
    memhook.realloc = dlsym(RTLD_NEXT, "realloc");
    memhook.memalign       = dlsym(RTLD_NEXT, "memalign");
    memhook.posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    memhook.aligned_alloc  = dlsym(RTLD_NEXT, "aligned_alloc");
    memhook.valloc  = dlsym(RTLD_NEXT, "valloc");
    memhook.pvalloc = dlsym(RTLD_NEXT, "pvalloc");
    memhook.free    = dlsym(RTLD_NEXT, "free");
#if EN_HOOK_IMPLICIT_ALLOC
    memhook.mmap   = dlsym(RTLD_NEXT, "mmap");
    memhook.mmap64 = dlsym(RTLD_NEXT, "mmap64");
    memhook.mremap = dlsym(RTLD_NEXT, "mremap");
    memhook.munmap = dlsym(RTLD_NEXT, "munmap");
#ifndef __GLIBC__
    memhook.brk  = dlsym(RTLD_NEXT, "brk");
    memhook.sbrk = dlsym(RTLD_NEXT, "sbrk");
#endif
#endif
}

__attribute__((destructor)) void memhook_deinit(void)
{
#ifdef __GLIBC__
    __libc_freeres();
#endif
    if (memhook.mem_total > 0) {
        printf(":-( %"PRIuPTR" bytes memory escaped!\n", memhook.mem_total);
    } else {
        printf(":-) all memory deallocated!\n");
    }
    fflush(stdout);
    return;
}

#if EN_HOOK_EXPLICIT_ALLOC
void *malloc(size_t size)
{
    void *ptr = memhook.malloc(size);
    if (ptr) {
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ptr;
}
void *calloc(size_t nmemb, size_t size)
{
    void *ptr = memhook.calloc(nmemb, size);
    if (ptr) {
        ht_insert(ptr, nmemb * size);
        __atomic_fetch_add(&memhook.mem_total, nmemb * size, __ATOMIC_RELAXED);
        memhook.callback(__func__, nmemb * size);
    }
    return ptr;
}
void *realloc(void *old_ptr, size_t size)
{
    size_t old_size = 0;
    Node *node, *prev;
    if (old_ptr && (node = ht_find(old_ptr, &prev)) == NULL) {
        MEMHOOK_LOG_BADPTR(__func__, old_ptr);
    }
    void *ptr = memhook.realloc(old_ptr, size);
    if (ptr) {
        if (node) {
            old_size = node->sz;
            ht_erase(prev, node);
        }
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size - old_size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size - old_size);
    }
    return ptr;
}

void *memalign(size_t boundary, size_t size)
{
    void *ptr = memhook.memalign(boundary, size);
    if (ptr) {
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    int ret = memhook.posix_memalign(memptr, alignment, size);
    if (ret == 0) {
        ht_insert(*memptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ret;
}
void *aligned_alloc(size_t alignment, size_t size)
{
    void *ptr = memhook.aligned_alloc(alignment, size);
    if (ptr) {
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ptr;
}

void free(void *ptr)
{
    if (!ptr) return;
    Node *node, *prev;
    if ((node = ht_find(ptr, &prev))) {
        size_t size = node->sz;
        ht_erase(prev, node);
        __atomic_fetch_add(&memhook.mem_total, -size, __ATOMIC_RELAXED);
        memhook.callback(__func__, -size);
    } else {
        MEMHOOK_LOG_BADPTR(__func__, ptr);
    }
    memhook.free(ptr);
}
void *valloc(size_t size)
{
    void *ptr = memhook.valloc(size);
    if (ptr) {
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ptr;
}
void *pvalloc(size_t size)
{
    void *ptr = memhook.pvalloc(size);
    if (ptr) {
        ht_insert(ptr, size);
        __atomic_fetch_add(&memhook.mem_total, size, __ATOMIC_RELAXED);
        memhook.callback(__func__, size);
    }
    return ptr;
}
#endif

#if EN_HOOK_IMPLICIT_ALLOC
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    return memhook.mmap(addr, length, prot, flags, fd, offset);
}
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset)
{
    return memhook.mmap64(addr, length, prot, flags, fd, offset);
}
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...)
{
    if (flags & MREMAP_FIXED) {
        va_list ap;
        va_start(ap, flags);
        void *fixed_addr = va_arg(ap, void *);
        va_end(ap);
        return memhook.mremap(old_addr, old_size, new_size, flags, fixed_addr);
    }
    return memhook.mremap(old_addr, old_size, new_size, flags);
}
int munmap(void *addr, size_t length)
{
    return memhook.munmap(addr, length);
}

#ifndef __GLIBC__
int brk(void *addr)
{
    return memhook.brk(addr);
}
void *sbrk(intptr_t increment)
{
    return memhook.sbrk(increment);
}
#endif
#endif
