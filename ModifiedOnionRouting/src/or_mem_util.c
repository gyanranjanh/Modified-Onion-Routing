/*
 * FILE:	or_mem_util.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_mem_util.h"

/*
 * or_mem_alloc:
 * Allocates size bytes 
 * returns pointer to allocated memory
 */
void *or_mem_alloc(OrSize size)
{
    return malloc(size);
}

/*
 * or_mem_free:
 * Frees 'ptr' 
 * returns nothing
 */
void or_mem_free(void *ptr)
{
    if(ptr != NULL) {
        free(ptr);
    }
}

/*
 * or_mem_copy:
 * Copy size bytes from 'src' to 'dst'
 * returns nothing
 */
void or_mem_copy(void *dst, void *src, OrSize size)
{
    bcopy(src, dst, size);
}

/*
 * or_mem_zero:
 * set the first 'size' bytes of the area starting at 'src' to zero (bytes containing '\0').
 * returns nothing
 */
void or_mem_zero(void *src, OrSize size)
{
    bzero(src, size);
}

OrInt32 or_mem_cmp(const void *buf1, const void *buf2, OrSize count)
{
    return memcmp(buf1, buf2, count);
}

void *or_mem_set(void *dest, OrUint8 c, OrSize count)
{
    return memset(dest, c, count);
}

