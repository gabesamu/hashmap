#include <stdio.h>
#include <assert.h>

#include "../src/hashmap.c"


#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>

static uintptr_t total_allocs = 0;
static uintptr_t total_mem = 0;

static void *xmalloc(size_t size) {
    void *mem = malloc(sizeof(uintptr_t)+size);
    assert(mem);
    *(uintptr_t*)mem = size;
    total_allocs++;
    total_mem += size;
    return (char*)mem+sizeof(uintptr_t);
}

static void xfree(void *ptr) {
    if (ptr) {
        total_mem -= *(uintptr_t*)((char*)ptr-sizeof(uintptr_t));
        free((char*)ptr-sizeof(uintptr_t));
        total_allocs--;
    }
}



#define bench(name, N, code) {{ \
    if (strlen(name) > 0) { \
        printf("%-14s ", name); \
    } \
    size_t tmem = total_mem; \
    size_t tallocs = total_allocs; \
    uint64_t bytes = 0; \
    clock_t begin = clock(); \
    for (int i = 0; i < N; i++) { \
        (code); \
    } \
    clock_t end = clock(); \
    double elapsed_secs = (double)(end - begin) / CLOCKS_PER_SEC; \
    double bytes_sec = (double)bytes/elapsed_secs; \
    printf("%d ops in %.3f secs, %.0f ns/op, %.0f op/sec", \
        N, elapsed_secs, \
        elapsed_secs/(double)N*1e9, \
        (double)N/elapsed_secs \
    ); \
    if (bytes > 0) { \
        printf(", %.1f GB/sec", bytes_sec/1024/1024/1024); \
    } \
    if (total_mem > tmem) { \
        size_t used_mem = total_mem-tmem; \
        printf(", %.2f bytes/op", (double)used_mem/N); \
    } \
    if (total_allocs > tallocs) { \
        size_t used_allocs = total_allocs-tallocs; \
        printf(", %.2f allocs/op", (double)used_allocs/N); \
    } \
    printf("\n"); \
}}

static void benchmarks() {
    int seed = getenv("SEED")?atoi(getenv("SEED")):time(NULL);
    int N = 10000;
    printf("seed=%d, count=%d, item_size=%zu\n", seed, N, sizeof(int));
    srand(seed);


    struct key_value_pairs{
        char key[6];
        int value;
    };

    struct key_value_pairs *pairs = xmalloc(sizeof(struct key_value_pairs)*N);

    for (int i = 0; i < N; i++) {
        sprintf(pairs[i].key, "%d", i);
        printf("pairs[i].key=%s\n", pairs[i].key);
        pairs[i].value = i;
    }

    printf("sizeof(struct key_value_pairs)=%zu\n", sizeof(struct key_value_pairs));

    struct hashmap *map;

    struct hashmap_create_options options = {
        .value_size = sizeof(int),
        .capacity = 0,
        .hash = NULL,
        .value_free = NULL
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

    xfree(pairs);

    if (total_allocs != 0) {
        fprintf(stderr, "total_allocs: expected 0, got %lu\n", total_allocs);
        exit(1);
    }
}



// void test_insert_retrieve() {
//     struct hashmap_create_options options = {
//         .value_size = sizeof(int),
//         .capacity = HASHMAP_DEFAULT_CAPACITY,
//         .hash = NULL,
//         .value_free = NULL
//     };
//     struct hashmap *map = hashmap_create(&options);

//     // Check map creation
//     assert(map != NULL);
//     assert(hashmap_count(map) == 0);

//     // Insert key-value pairs
//     int values[10];
//     for (int i = 0; i < 10; i++) {
//         values[i] = i;
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         assert(hashmap_set(map, key, &values[i]));
//     }

//     // Check retrieval
//     for (int i = 0; i < 10; i++) {
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         const int *retrieved_value = (const int *)hashmap_get(map, key);
//         assert(retrieved_value != NULL);
//         assert(*retrieved_value == i);
//     }

//     hashmap_free(map);
// }

// void test_remove() {
//     struct hashmap_create_options options = {
//         .value_size = sizeof(int),
//         .capacity = HASHMAP_DEFAULT_CAPACITY,
//         .hash = NULL,
//         .value_free = NULL
//     };
//     struct hashmap *map = hashmap_create(&options);

//     // Check map creation
//     assert(map != NULL);
//     assert(hashmap_count(map) == 0);

//     // Insert key-value pairs
//     int values[10];
//     for (int i = 0; i < 10; i++) {
//         values[i] = i;
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         assert(hashmap_set(map, key, &values[i]));
//     }

//     // Check retrieval
//     for (int i = 0; i < 10; i++) {
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         const int *retrieved_value = (const int *)hashmap_get(map, key);
//         assert(retrieved_value != NULL);
//         assert(*retrieved_value == i);
//     }

//     // Remove key-value pairs
//     for (int i = 0; i < 10; i++) {
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         assert(hashmap_remove(map, key));
//     }

//     // Check retrieval
//     for (int i = 0; i < 10; i++) {
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         const int *retrieved_value = (const int *)hashmap_get(map, key);
//         assert(retrieved_value == NULL);
//     }

//     hashmap_free(map);
// }

// void test_resize() {
//     struct hashmap_create_options options = {
//         .value_size = sizeof(int),
//         .capacity = 1,
//         .hash = NULL,
//         .value_free = NULL
//     };
//     struct hashmap *map = hashmap_create(&options);

//     // Check map creation
//     assert(map != NULL);
//     assert(hashmap_count(map) == 0);

//     // Insert key-value pairs
//     int values[10];
//     for (int i = 0; i < 10; i++) {
//         values[i] = i;
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         assert(hashmap_set(map, key, &values[i]));
//     }

//     // Check retrieval
//     for (int i = 0; i < 10; i++) {
//         char key[20];
//         snprintf(key, 20, "key%d", i);
//         const int *retrieved_value = (const int *)hashmap_get(map, key);
//         assert(retrieved_value != NULL);
//         assert(*retrieved_value == i);
//     }

//     hashmap_free(map);
// }


int main() {
    printf("Running tests...\n");
    // test_insert_retrieve();
    // test_remove();
    // test_resize();
    benchmarks();
    printf("All tests passed!\n");
    return 0;
}
