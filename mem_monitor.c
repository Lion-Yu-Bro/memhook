#include <stdlib.h>

#define TEST_MALLOC         1
#define TEST_CALLOC         1
#define TEST_REALLOC        1 // maybe call malloc when old_ptr is NULL
#define TEST_FREE           0 // enable this to check whether 'free' can detect double free
#define TEST_REALLOCARRAY   1 // do not hook, otherwise will result in duplicate counting with 'realloc'
#define TEST_POSIX_MEMALIGN 1
#define TEST_ALIGN_ALLOC    1
#define TEST_MEMALIGN       0 // not support
#define TEST_STRDUP         0 // do not hook, otherwise will result in duplicate counting with 'malloc'
#define TEST_STRNDUP        0 // do not hook, otherwise will result in duplicate counting with 'malloc'
#define TEST_VALLOC         1
#define TEST_PVALLOC        0 // not support

int main(int argc, char *argv[])
{
    char *ptr;
#if TEST_MALLOC
    ptr = malloc(16);
    free(ptr);
#endif
#if TEST_CALLOC
    ptr = calloc(1, 24);
#if !TEST_REALLOC
    free(ptr);
#endif
#endif
#if TEST_REALLOC
    ptr = realloc(ptr, 32);
    free(ptr);
    ptr = realloc(NULL, 16);
#if !TEST_REALLOCARRAY
    free(ptr);
#endif
#endif
#if TEST_REALLOCARRAY
    ptr = reallocarray(ptr, 2, 32);
    free(ptr);
#endif
#if TEST_POSIX_MEMALIGN
    int ret = posix_memalign((void**)&ptr, 8, 72);
    if (ret == 0) free(ptr);
#endif
#if TEST_ALIGN_ALLOC
    ptr = aligned_alloc(16, 36);
    free(ptr);
#endif
#if TEST_MEMALIGN
    ptr = memalign(16, 128);
    free(ptr);
#endif
#if TEST_STRDUP
    ptr = strdup(argv[0]);
    free(ptr);
#endif
#if TEST_STRNDUP
    ptr = strndup(argv[0], 5);
    free(ptr);
#endif
#if TEST_VALLOC
    ptr = valloc(512);
    free(ptr);
#endif
#if TEST_PVALLOC
    ptr = pvalloc(512);
    free(ptr);
#endif
#if TEST_FREE
    free(ptr);
#endif
    return 0;
}
