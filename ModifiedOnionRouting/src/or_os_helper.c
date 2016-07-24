/*
 * FILE:	or_os_helper.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_os_helper.h"
#include "or_mem_util.h"

/* --------------------------------------------------------------------------
 * Initialise the mutex so that it can be used to lock
 * areas of code */
OrBool or_mutex_create(OrMutexHandle *mutex)
{
    OrBool result = FALSE;

    if (mutex == NULL)
    {
        goto OUT;;
    }

    *mutex = (pthread_mutex_t *)or_mem_alloc(sizeof(pthread_mutex_t));

    if (pthread_mutex_init(*mutex, NULL) == 0)
    {
        result = TRUE;
    }

OUT:
    return result;
}

/* --------------------------------------------------------------------------
 * Destroys the mutex so that the associate resources are freed
 */
void or_mutex_destroy(OrMutexHandle mutex)
{
    if(mutex != NULL) {
        pthread_mutex_destroy(mutex);
        or_mem_free(mutex);
    }
}

/* --------------------------------------------------------------------------
 * Marks the code following this function as critical. This means no other
 * context that uses the same critical section handle may execute the code
 */
OrBool or_mutex_lock(OrMutexHandle mutex)
{
    OrBool result = FALSE;

    if (mutex == NULL)
    {
        goto OUT;
    }

    if (pthread_mutex_lock(mutex) == 0)
    {
        result = TRUE;
    }

OUT:
    return result;
}

/* --------------------------------------------------------------------------
 * Marks the end of the critical section - many execution contexts may
 * execute the code after this call.
 */
OrBool or_mutex_unlock(OrMutexHandle mutex)
{
    OrBool result = FALSE;

    if (mutex == NULL)
    {
        goto OUT;
    }

    if (pthread_mutex_unlock(mutex) == 0)
    {
        result = TRUE;
    }

OUT:
    return result;
}

OrBool or_sema_create(OrSemaHandle *sema) 
{
    OrBool result = FALSE;

    if (sema == NULL)
    {
        goto OUT;;
    }

    if(!sem_init(sema, 0, 1))
    {
        result = TRUE;
    }

OUT:
    return result;
}

OrBool or_sema_wait(OrSemaHandle *sema)
{
    OrBool result = FALSE;

    if (sema == NULL)
    {
        goto OUT;;
    }

    if(!sem_wait(sema))
    {
        result = TRUE;
    }

OUT:
    return result;
}

OrBool or_sema_release(OrSemaHandle *sema)
{
    OrBool result = FALSE;

    if (sema == NULL)
    {
        goto OUT;;
    }

    if(!sem_post(sema))
    {
        result = TRUE;
    }

OUT:
    return result;
}

OrBool or_sema_destroy(OrSemaHandle *sema) 
{
    OrBool result = FALSE;

    if (sema == NULL)
    {
        goto OUT;;
    }

    if(!sem_destroy(sema))
    {
        result = TRUE;
    }

OUT:
    return result;
}