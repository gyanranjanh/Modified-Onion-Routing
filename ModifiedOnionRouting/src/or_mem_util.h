/*
 * FILE:	or_mem_util.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_MEM_UTIL_H__
#define __OR_MEM_UTIL_H__

#include "or_types.h"

void *or_mem_alloc(OrSize size);
void or_mem_free(void *ptr);
void or_mem_copy(void *dst, void *src, OrSize size);
void or_mem_zero(void *src, OrSize size);

#endif /* __OR_MEM_UTIL_H_ */
