#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>

// #define HASHMAP_KEY_SIZE 10
#include "../src/hashmap.c"



static uintptr_t total_allocs = 0;
static uintptr_t total_mem = 0;
static uintptr_t live_allocs = 0;

static void *test_malloc(size_t size) {
    void *mem = malloc(sizeof(uintptr_t)+size);
    assert(mem);
    *(uintptr_t*)mem = size;
    total_allocs++;
    live_allocs++;
    total_mem += size;
    return (char*)mem+sizeof(uintptr_t);
}

static void test_free(void *ptr) {
    if (ptr) {
        total_mem -= *(uintptr_t*)((char*)ptr-sizeof(uintptr_t));
        free((char*)ptr-sizeof(uintptr_t));
        live_allocs--;
    }
}



#define bench(name, N, code) {{ \
    if (strlen(name) > 0) { \
        printf("%-14s ", name); \
    } \
    size_t tmem = total_mem; \
    size_t tallocs = total_allocs; \
    clock_t begin = clock(); \
    for (int i = 0; i < N; i++) { \
        (code); \
    } \
    clock_t end = clock(); \
    double elapsed_secs = (double)(end - begin) / CLOCKS_PER_SEC; \
    printf("%d ops in %.3f secs, %.0f ns/op, %.0f op/sec", \
        N, elapsed_secs, \
        elapsed_secs/(double)N*1e9, \
        (double)N/elapsed_secs \
    ); \
    printf(", size: %lu Kb", total_mem/1024); \
    if (total_mem > tmem) { \
        size_t used_mem = total_mem-tmem; \
        printf(", %.2f bytes/op", (double)used_mem/N); \
    } \
    if (total_allocs > tallocs) { \
        size_t used_allocs = total_allocs-tallocs; \
        printf(", %.2f allocs", (double)used_allocs); \
    } \
    printf("\n"); \
}}

static void benchmarks() {
    int seed = getenv("SEED")?atoi(getenv("SEED")):time(NULL);
    int N = 1000000;
    srand(seed);

    struct key_value_pairs{
        char key[10];
        int value;
    };

    struct key_value_pairs *pairs = test_malloc(sizeof(struct key_value_pairs)*N);

    for (int i = 0; i < N; i++) {
        sprintf(pairs[i].key, "%d", i);
        pairs[i].value = i;
    }

    struct hashmap *map;

    struct hashmap_create_options options = {
        .value_size = sizeof(int),
        .capacity = 0,
        .hash = NULL,
        .value_free = NULL,
        .custom_malloc = test_malloc,
        .custom_free = test_free
    };
    map = hashmap_create(&options);
    // benchmark ops with default capacity
    bench("set", N, {
        const bool res = hashmap_set(map, pairs[i].key, &pairs[i].value);
        assert(res == true);
    })
    bench("get", N, {
        const int *v = hashmap_get(map, pairs[i].key);
        assert(v && *v == pairs[i].value);
    })
    bench("delete", N, {
        const bool res = hashmap_remove(map, pairs[i].key);
        assert(res == true);
    })
    hashmap_free(map);

    // benchmark ops with capacity set
    options.capacity = N;
    map = hashmap_create(&options);
    bench("set (cap)", N, {
        const bool res = hashmap_set(map, pairs[i].key, &pairs[i].value);
        assert(res == true);
    })
    bench("get (cap)", N, {
        const int *v = hashmap_get(map, pairs[i].key);
        assert(v && *v == pairs[i].value);
    })
    bench("delete (cap)" , N, {
        const bool res = hashmap_remove(map, pairs[i].key);
        assert(res == true);
    })

    hashmap_free(map);

    test_free(pairs);

    if (live_allocs != 0) {
        fprintf(stderr, "live_allocs: expected 0, got %lu\n", live_allocs);
        exit(1);
    }
}



int main() {
    printf("Running tests...\n");
    benchmarks();
    printf("All tests passed!\n");
    return 0;
}
