/*
 * FILE:	or_os_helper.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_OS_HELPER_H__
#define __OR_OS_HELPER_H__

#include "or_types.h"

OrBool or_mutex_create(OrMutexHandle* mutex);
void or_mutex_destroy(OrMutexHandle mutex);
OrBool or_mutex_lock(OrMutexHandle mutex);
OrBool or_mutex_unlock(OrMutexHandle mutex);

#endif /* __OR_OS_HELPER_H__ */

