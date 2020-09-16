
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4020226c209c432eb8a21752fdbc9e41)](https://www.codacy.com/manual/GlitchedPolygons/chillbuff?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/chillbuff&amp;utm_campaign=Badge_Grade)
[![Build status](https://ci.appveyor.com/api/projects/status/hru1ndvsobkay374/branch/master?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/chillbuff/branch/master)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/chillbuff.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/chillbuff)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/chillbuff/blob/master/LICENSE)

# ChillBuff
## A super simple, [header-](https://github.com/GlitchedPolygons/chillbuff/blob/master/include/chillbuff.h)[only](https://en.wikipedia.org/wiki/Header-only) and [Apache-2.0 licensed](https://github.com/GlitchedPolygons/chillbuff/blob/master/LICENSE) dynamic-size array

> ᐳᐳ  Check out the API docs [here on github.io](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html)

### How to build

Just add the [`include/chillbuff.h`](https://github.com/GlitchedPolygons/chillbuff/blob/master/include/chillbuff.h) header file to your project and you're good to go!

### What is this?

An array that resizes itself when its maximum capacity is reached. Nothing super fancy either: you can only add and not remove. 

Mostly useful as a string builder of some sort, but you can obviously also use it for ints, structs, etc...

### How to use

Let's say you want to build an array of integers, characters or whatever, whose total element count you don't know yet. 
 
Without needing to manually check the available slots, keep track/decrease/increase some values, etc... you can just [`init`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#a844e0218ca5032f0daa183b7d54ab7ef) a [`chillbuff`](https://glitchedpolygons.github.io/chillbuff/structchillbuff.html) instance (try to give a rough guess when it comes to initial capacity, [`growth method`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#a97927f423ae597adaf00d6636d953c4d), etc...) and then [`push_back`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#ace76acc79c303bbe52210d6ba7765b43) and chill! No need to worry about resizing or any of that stuff. It's all taken care of for you in the background. How comfortable!

When you're done adding to the buffer, you can access its underlying array using the [`chillbuff.array`](https://glitchedpolygons.github.io/chillbuff/structchillbuff.html#ac8c010be0c6998052548372f7d33e614) and [`chillbuff.length`](https://glitchedpolygons.github.io/chillbuff/structchillbuff.html#a8920604755c2669c46a9c28d42c19b4a) fields.
 
You can also [`clear`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#a8882aaee3d6540ba9c87e520ce3eb1fc) the buffer: this will reset its [`length`](https://glitchedpolygons.github.io/chillbuff/structchillbuff.html#a8920604755c2669c46a9c28d42c19b4a) to `0` and delete all of its content (the capacity remains untouched though: the underlying array **won't be shrinked**!).

If you want you can set up an error message callback using the [`set_error_callback`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#a97a3a7a54756cdd4ecf7357e3f30412f) function: pass in a void function pointer that takes 1 `const char*` parameter. If a chillbuff error occurs, its human-readable error message will be passed as a string into the provided callback function. Could be some sort of `printf`, or one of your own error log file writer functions. 

To remove the callback (stop calling the callback and passing error messages into it), just call [`unset_error_callback`](https://glitchedpolygons.github.io/chillbuff/chillbuff_8h.html#ac6713a05d7aaf6afb19bf254a9159408).

#### Strings

```C
    #include <chillbuff.h>

    chillbuff stringbuilder;
    
    /* 
     * Initialize a chillbuff that stores a C-style string. 
     * You can append one character or entire strings to it using the push_back function!
     */
    chillbuff_init(&stringbuilder, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);

    const char* add1 = "Hello ";
    const char* add2 = "World!";

    /* Add some strings to the buffer. NUL-terminator is appended automatically. */
    chillbuff_push_back(&stringbuilder, add1, strlen(add1));
    chillbuff_push_back(&stringbuilder, add2, strlen(add1));

    /* Do something with the constructed string. */
    printf("%s \n", stringbuilder.array);
    printf("String length: %d \n", (int)stringbuilder.length);

    /* Never forget to free the buffer once you're done using it! */
    chillbuff_free(&stringbuilder);
```
 
---

#### Other types

```C
    #include <chillbuff.h>
    
    chillbuff buffer;
    
    /* 
     * Initialize a chillbuff that stores elements of type `uint16_t` 
     * and duplicates its capacity once it's full. Give it an initial 
     * capacity of 2, just to demonstrate that it resizes correctly.
     */
    chillbuff_init(&buffer, 2, sizeof(uint16_t), CHILLBUFF_GROW_DUPLICATIVE);

    uint16_t add1[] = { 1, 2, 3 };
    uint16_t add2[] = { 4, 5, 6, 7, 8, 9, 100, 200, 300 };

    /* r1 and r2 will contain the returned exit code. If something fails, that is >0 */
    int r1 = chillbuff_push_back(&buffer, add1, sizeof(add1) / sizeof(uint16_t));
    int r2 = chillbuff_push_back(&buffer, add2, sizeof(add2) / sizeof(uint16_t));

    /* 
     * Check out the numbers in the buffer: they match the added ones! 
     * Now you can do something with this array 
     */
    uint16_t n0 = ((uint16_t*)buffer.array)[0];
    uint16_t n1 = ((uint16_t*)buffer.array)[1]; /* This syntax is how you need to dereference/access the array. */
    uint16_t n2 = ((uint16_t*)buffer.array)[2];
    uint16_t n3 = ((uint16_t*)buffer.array)[3];
    uint16_t n4 = ((uint16_t*)buffer.array)[4];
    uint16_t n5 = ((uint16_t*)buffer.array)[5];
    /* (etc...) */
    
    /* Never forget to free the buffer once you're done using it! */
    chillbuff_free(&buffer);
```
