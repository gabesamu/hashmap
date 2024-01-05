#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/hashmap.h"


// This will set the size of the maximum physical string the can be stored as a key.
// Any string longer than this will be stored dynamically as a pointer.
// This can be overridden by defining HASHMAP_KEY_SIZE before including this header.
// warning: don't overallocate this value to avoid wasting memory
#ifndef HASHMAP_KEY_SIZE
#define HASHMAP_KEY_SIZE sizeof(char *)
#elif HASHMAP_KEY_SIZE < sizeof(char *)
#undef HASHMAP_KEY_SIZE
#define HASHMAP_KEY_SIZE sizeof(char *)
#endif

#ifndef HASHMAP_MAX_LOAD_FACTOR
#define HASHMAP_MAX_LOAD_FACTOR 0.60
#endif

#ifndef HASHMAP_MIN_LOAD_FACTOR
#define HASHMAP_MIN_LOAD_FACTOR 0.10
#endif

// Note: The capacity of the hashmap should typically be kept as be a power of 2 for efficiency
#ifndef HASHMAP_DEFAULT_CAPACITY
#define HASHMAP_DEFAULT_CAPACITY 32
#endif

struct bucket {
    uint64_t hash;
    uint16_t probe_len;
    bool is_key_ptr;
    union Key {
        char key[HASHMAP_KEY_SIZE];
        char *key_ptr;
    } key;
};

struct hashmap {
    size_t value_size;
    size_t capacity;
    uint64_t seed1;
    uint64_t seed2;
    uint64_t (*key_hash)(const void *key, size_t len, uint64_t seed1, uint64_t seed2);
    void (*value_free)(void *value);
    void *buckets;
    size_t bucket_size;
    size_t grow_at;
    size_t shrink_at;
    size_t num_buckets;
    size_t num_elements;
    void *temp_bucket;
    void *insertion_bucket;
};

static struct bucket* get_bucket(const struct hashmap *map, size_t index) {
    return (struct bucket *)(((char *)map->buckets) + (index * map->bucket_size));
}

static void *get_value(struct bucket *bucket) {
    return ((char *)bucket) + sizeof(struct bucket);
}

static void set_key(struct bucket *bucket, const char *key) {
    if (strlen(key) > HASHMAP_KEY_SIZE) {
        bucket->is_key_ptr = true;
        bucket->key.key_ptr = strdup(key);
    }
    else {
        bucket->is_key_ptr = false;
        memcpy(bucket->key.key, key, HASHMAP_KEY_SIZE);
    }
}

static const char *get_key(struct bucket *bucket) {
    if (bucket->is_key_ptr) {
        return bucket->key.key_ptr;
    }
    return bucket->key.key;
}


static void free_values(struct hashmap *map) {
    if (map->value_free) {
        for (size_t i = 0; i < map->num_buckets; i++) {
            struct bucket *bucket = get_bucket(map, i);
            if (bucket->hash) {
                map->value_free(get_value(bucket));
            }
        }
    }
}

void hashmap_set_seeds(struct hashmap *map, uint64_t seed1, uint64_t seed2) {
    map->seed1 = seed1;
    map->seed2 = seed2;
}

struct hashmap *hashmap_create(const struct hashmap_create_options *options) {

    size_t bucket_size = sizeof(struct bucket) + options->value_size;

    // Align bucket size to the word size of the machine
    while (bucket_size & (sizeof(uintptr_t) - 1)) {
        bucket_size++;
    }

    struct hashmap *map = malloc(sizeof(struct hashmap) + bucket_size*2);
    if (!map) {
        return NULL;
    }
    memset(map, 0, sizeof(struct hashmap));

    size_t cap = HASHMAP_DEFAULT_CAPACITY;
    while (cap < options->capacity) {
        cap *= 2;
    }

    map->buckets = malloc(bucket_size * cap);
    if (!map->buckets) {
        free(map);
        return NULL;
    }
    memset(map->buckets, 0, bucket_size * cap);

    map->value_size = options->value_size;
    map->capacity = cap;
    map->seed1 = 0;
    map->seed2 = 0;
    map->key_hash = options->hash ? options->hash : hashmap_murmur;
    map->value_free = options->value_free;
    map->bucket_size = bucket_size;
    map->num_buckets = cap;
    map->temp_bucket = ((char *)map) + sizeof(struct hashmap);
    map->insertion_bucket = ((char *)map) + sizeof(struct hashmap) + bucket_size;
    map->grow_at = map->num_buckets * HASHMAP_MAX_LOAD_FACTOR;
    map->shrink_at = map->num_buckets * HASHMAP_MIN_LOAD_FACTOR;

    return map;
}

static bool resize(struct hashmap *map, size_t new_capacity) {
    struct hashmap_create_options options = {
        .value_size = map->value_size,
        .capacity = new_capacity,
    };

    struct hashmap *temp_map = hashmap_create(&options);
    if (!temp_map) return false;

    struct bucket *src, *dst;

    for (size_t i = 0; i < map->num_buckets; i++) {
        src = get_bucket(map, i);
        if (!src->hash) {
            continue;
        }

        src->probe_len = 0;
        size_t dst_idx = src->hash & (temp_map->num_buckets - 1);
        while(true) {
            dst = get_bucket(temp_map, dst_idx);
            if (!dst->hash) {
                memcpy(dst, src, map->bucket_size);
                break;
            }

            if (dst->probe_len < src->probe_len) {
                memcpy(temp_map->temp_bucket, dst, map->bucket_size);
                memcpy(dst, src, map->bucket_size);
                memcpy(src, temp_map->temp_bucket, map->bucket_size);
            }

            dst_idx = (dst_idx + 1) & (temp_map->num_buckets - 1);
            src->probe_len++;
        }
    }

    free(map->buckets);
    map->buckets = temp_map->buckets;
    map->num_buckets = temp_map->num_buckets;
    map->grow_at = temp_map->grow_at;
    map->shrink_at = temp_map->shrink_at;
    free(temp_map);

    return true;
}

bool hashmap_set(struct hashmap *map, const char *key, const void *value) {
    uint64_t hash = map->key_hash(key, strlen(key), map->seed1, map->seed2);
    // printf("hash: %llu\n", hash);


    if (map->num_elements >= map->grow_at) {
        if (!resize(map, map->num_buckets * 2)) {
            return false;
        }
    }

    struct bucket *src = map->insertion_bucket;
    src->hash = hash;
    src->probe_len = 0;
    set_key(src, key);
    memcpy(get_value(src), value, map->value_size);

    size_t idx = src->hash & (map->num_buckets - 1);

    while (true) {
        struct bucket *dst = get_bucket(map, idx);
        if (!dst->hash) {
            memcpy(dst, src, map->bucket_size);
            map->num_elements++;
            return true;
        }

        if (dst->hash == src->hash && strcmp(get_key(dst), get_key(src)) == 0) {
            memcpy(get_value(dst), value, map->value_size);
            return true;
        }

        if (dst->probe_len < src->probe_len) {
            memcpy(map->temp_bucket, dst, map->bucket_size);
            memcpy(dst, src, map->bucket_size);
            memcpy(src, map->temp_bucket, map->bucket_size);
        }

        idx = (idx + 1) & (map->num_buckets - 1);
        src->probe_len++;
    }
}

const void *hashmap_get(const struct hashmap *map, const char *key) {
    // printf("key: %s\n", key);
    uint64_t hash = map->key_hash(key, strlen(key), map->seed1, map->seed2);
    size_t idx = hash & (map->num_buckets - 1);
    // printf("hash: %llu\n", hash);
    // printf("idx: %d\n", idx);

    while (true) {
        struct bucket *bucket = get_bucket(map, idx);
        if (!bucket->hash) {
            printf("not found\n");
            return NULL;
        }

        if (bucket->hash == hash && strcmp(get_key(bucket), key) == 0) {
            return get_value(bucket);
        }

        idx = (idx + 1) & (map->num_buckets - 1);
    }
}

bool hashmap_remove(struct hashmap *map, const char *key) {
    uint64_t hash = map->key_hash(key, strlen(key), map->seed1, map->seed2);
    size_t idx = hash & (map->num_buckets - 1);

    while (true) {
        struct bucket *bucket = get_bucket(map, idx);
        if (!bucket->hash) {
            return false;
        }

        if (bucket->hash == hash && strcmp(get_key(bucket), key) == 0) {
            bucket->hash = 0;
            map->num_elements--;

            while (true) {
                size_t next_idx = (idx + 1) & (map->num_buckets - 1);
                struct bucket *next_bucket = get_bucket(map, next_idx);
                if (!next_bucket->hash || next_bucket->probe_len == 0) {
                    bucket->hash = 0;
                    bucket->probe_len = 0;
                    break;
                }

                memcpy(bucket, next_bucket, map->bucket_size);
                bucket->probe_len--;

                idx = next_idx;
                bucket = next_bucket;
            }

            if (map->num_elements <= map->shrink_at && map->num_buckets > HASHMAP_DEFAULT_CAPACITY) {
                resize(map, map->num_buckets / 2);
            }

            return true;
        }

        idx = (idx + 1) & (map->num_buckets - 1);
    }
}

void hashmap_free(struct hashmap *map) {
    if (!map) {
        return;
    }
    free_values(map);
    free(map->buckets);
    free(map);
}

size_t hashmap_count(const struct hashmap *map) {
    return map->num_elements;
}



// MurmurHash 3 by Austin Appleby

static uint64_t MM86128(const void *key, const int len, uint32_t seed) {
    #define	ROTL32(x, r) ((x << r) | (x >> (32 - r)))
    #define FMIX32(h) h^=h>>16; h*=0x85ebca6b; h^=h>>13; h*=0xc2b2ae35; h^=h>>16;
        const uint8_t * data = (const uint8_t*)key;
        const int nblocks = len / 16;
        uint32_t h1 = seed;
        uint32_t h2 = seed;
        uint32_t h3 = seed;
        uint32_t h4 = seed;
        uint32_t c1 = 0x239b961b;
        uint32_t c2 = 0xab0e9789;
        uint32_t c3 = 0x38b34ae5;
        uint32_t c4 = 0xa1e38b93;
        const uint32_t * blocks = (const uint32_t *)(data + nblocks*16);
        for (int i = -nblocks; i; i++) {
            uint32_t k1 = blocks[i*4+0];
            uint32_t k2 = blocks[i*4+1];
            uint32_t k3 = blocks[i*4+2];
            uint32_t k4 = blocks[i*4+3];
            k1 *= c1; k1  = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
            h1 = ROTL32(h1,19); h1 += h2; h1 = h1*5+0x561ccd1b;
            k2 *= c2; k2  = ROTL32(k2,16); k2 *= c3; h2 ^= k2;
            h2 = ROTL32(h2,17); h2 += h3; h2 = h2*5+0x0bcaa747;
            k3 *= c3; k3  = ROTL32(k3,17); k3 *= c4; h3 ^= k3;
            h3 = ROTL32(h3,15); h3 += h4; h3 = h3*5+0x96cd1c35;
            k4 *= c4; k4  = ROTL32(k4,18); k4 *= c1; h4 ^= k4;
            h4 = ROTL32(h4,13); h4 += h1; h4 = h4*5+0x32ac3b17;
        }
        const uint8_t * tail = (const uint8_t*)(data + nblocks*16);
        uint32_t k1 = 0;
        uint32_t k2 = 0;
        uint32_t k3 = 0;
        uint32_t k4 = 0;
        switch(len & 15) {
        case 15: k4 ^= tail[14] << 16; /* fall through */
        case 14: k4 ^= tail[13] << 8; /* fall through */
        case 13: k4 ^= tail[12] << 0;
                 k4 *= c4; k4  = ROTL32(k4,18); k4 *= c1; h4 ^= k4;
                 /* fall through */
        case 12: k3 ^= tail[11] << 24; /* fall through */
        case 11: k3 ^= tail[10] << 16; /* fall through */
        case 10: k3 ^= tail[ 9] << 8; /* fall through */
        case  9: k3 ^= tail[ 8] << 0;
                 k3 *= c3; k3  = ROTL32(k3,17); k3 *= c4; h3 ^= k3;
                 /* fall through */
        case  8: k2 ^= tail[ 7] << 24; /* fall through */
        case  7: k2 ^= tail[ 6] << 16; /* fall through */
        case  6: k2 ^= tail[ 5] << 8; /* fall through */
        case  5: k2 ^= tail[ 4] << 0;
                 k2 *= c2; k2  = ROTL32(k2,16); k2 *= c3; h2 ^= k2;
                 /* fall through */
        case  4: k1 ^= tail[ 3] << 24; /* fall through */
        case  3: k1 ^= tail[ 2] << 16; /* fall through */
        case  2: k1 ^= tail[ 1] << 8; /* fall through */
        case  1: k1 ^= tail[ 0] << 0;
                 k1 *= c1; k1  = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
                 /* fall through */
        };
        h1 ^= len; h2 ^= len; h3 ^= len; h4 ^= len;
        h1 += h2; h1 += h3; h1 += h4;
        h2 += h1; h3 += h1; h4 += h1;
        FMIX32(h1); FMIX32(h2); FMIX32(h3); FMIX32(h4);
        h1 += h2; h1 += h3; h1 += h4;
        h2 += h1; h3 += h1; h4 += h1;
        return (((uint64_t)h2)<<32)|h1;
    }



// SipHash 2-4 by Jean-Philippe Aumasson and Daniel J. Bernstein
    static uint64_t SIP64(const uint8_t *in, const size_t inlen, uint64_t seed0,
        uint64_t seed1)
    {
    #define U8TO64_LE(p) \
        {  (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) | \
            ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) | \
            ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) | \
            ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56)) }
    #define U64TO8_LE(p, v) \
        { U32TO8_LE((p), (uint32_t)((v))); \
          U32TO8_LE((p) + 4, (uint32_t)((v) >> 32)); }
    #define U32TO8_LE(p, v) \
        { (p)[0] = (uint8_t)((v)); \
          (p)[1] = (uint8_t)((v) >> 8); \
          (p)[2] = (uint8_t)((v) >> 16); \
          (p)[3] = (uint8_t)((v) >> 24); }
    #define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
    #define SIPROUND \
        { v0 += v1; v1 = ROTL(v1, 13); \
          v1 ^= v0; v0 = ROTL(v0, 32); \
          v2 += v3; v3 = ROTL(v3, 16); \
          v3 ^= v2; \
          v0 += v3; v3 = ROTL(v3, 21); \
          v3 ^= v0; \
          v2 += v1; v1 = ROTL(v1, 17); \
          v1 ^= v2; v2 = ROTL(v2, 32); }
        uint64_t k0 = U8TO64_LE((uint8_t*)&seed0);
        uint64_t k1 = U8TO64_LE((uint8_t*)&seed1);
        uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
        uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
        uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
        uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
        const uint8_t *end = in + inlen - (inlen % sizeof(uint64_t));
        for (; in != end; in += 8) {
            uint64_t m = U8TO64_LE(in);
            v3 ^= m;
            SIPROUND; SIPROUND;
            v0 ^= m;
        }
        const int left = inlen & 7;
        uint64_t b = ((uint64_t)inlen) << 56;
        switch (left) {
        case 7: b |= ((uint64_t)in[6]) << 48; /* fall through */
        case 6: b |= ((uint64_t)in[5]) << 40; /* fall through */
        case 5: b |= ((uint64_t)in[4]) << 32; /* fall through */
        case 4: b |= ((uint64_t)in[3]) << 24; /* fall through */
        case 3: b |= ((uint64_t)in[2]) << 16; /* fall through */
        case 2: b |= ((uint64_t)in[1]) << 8; /* fall through */
        case 1: b |= ((uint64_t)in[0]); break;
        case 0: break;
        }
        v3 ^= b;
        SIPROUND; SIPROUND;
        v0 ^= b;
        v2 ^= 0xff;
        SIPROUND; SIPROUND; SIPROUND; SIPROUND;
        b = v0 ^ v1 ^ v2 ^ v3;
        uint64_t out = 0;
        U64TO8_LE((uint8_t*)&out, b);
        return out;
    }


    uint64_t hashmap_murmur(const void *key, size_t len, uint64_t seed1, uint64_t seed2) {
        return MM86128(key, len, seed1);
    }

    uint64_t hashmap_sip(const void *key, size_t len, uint64_t seed1, uint64_t seed2) {
        return SIP64(key, len, seed1, seed2);
    }
