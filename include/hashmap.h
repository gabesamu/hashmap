#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


struct hashmap_create_options {

    // Mandatory: specifies the size of the values stored in the hashmap.
    // All values must be of this size.
    size_t value_size;

    // Optional: initial capacity of the hashmap.
    // If 0, the hashmap will start with a default capacity of 32.
    size_t capacity;

    // Optional: function to free values. Needed for values that require special cleanup of dynamic memory
    // (e.g., structs with dynamic memory). This is called when values are removed or when the map is freed.
    void (*value_free)(void *value);

    // Optional: The hash function to use. If NULL, this will default to using Murmur3.
    uint64_t (*hash)(const void *key, size_t len, uint64_t seed1, uint64_t seed2);

    void *(*custom_malloc)(size_t size);
    void (*custom_free)(void *ptr);
};

struct hashmap;

struct hashmap *hashmap_create(const struct hashmap_create_options *options);


void hashmap_free(struct hashmap *map);
const void *hashmap_get(const struct hashmap *map, const char *key);
bool hashmap_set(struct hashmap *map, const char *key, const void *value);
bool hashmap_remove(struct hashmap *map, const char *key);
size_t hashmap_size(const struct hashmap *map);
size_t hashmap_count(const struct hashmap *map);

void hashmap_set_seeds(struct hashmap *map, uint64_t seed1, uint64_t seed2);
uint64_t hashmap_murmur(const void *key, size_t len, uint64_t seed1, uint64_t seed2);
uint64_t hashmap_sip(const void *key, size_t len, uint64_t seed1, uint64_t seed2);









#endif
