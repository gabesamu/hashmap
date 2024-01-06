## Features

- Currently supports string keys and any generic value
- Simple interface with good defaults for many use cases
- Support for custom hashing functions and custom memory allocators
- Works with C99 and up

## Usage

```c
#include <stdio.h>
#include <string.h>

#include "hashmap.h"

struct value {
    int x;
    int y;
};

int main() {
    // creating a new hashmap
    // -----------------------------
    // using defaults and simple POD data just requires the size of whatever you're storing
    struct hashmap *map = hashmap_create(sizeof(value));

    // inserting key-value pairs. 2nd arugument is the key, 3rd is the value
    // -----------------------------
    hashmap_set(map, "hello", &(struct value){ .x = 1, .y = 2 });
    hashmap_set(map, "world", &(struct value){ .x = 3, .y = 4 });

    // getting values from the map using the key
    // -----------------------------
    struct value *val;
    val = hashmap_get(map, "hello");
    printf("hello: %d %d\n", val->x, val->y);

    val = hashmap_get(map, "world");
    printf("world: %d %d\n", val->x, val->y);

    // removing values from the map using the key
    // -----------------------------
    hashmap_remove(map, "hello");
    val = hashmap_get(map, "hello");
    printf("hello: %p\n", val); // should be NULL

    // freeing the map when done
    // -----------------------------
    hashmap_free(map);
    return 0;

}


```
