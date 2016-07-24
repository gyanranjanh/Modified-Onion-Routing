/*
 * FILE:	or_util.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_UTIL_H__
#define __OR_UTIL_H__

#include "or_types.h"

#define UNUSED(X)

#define SOCKET_BUF_LEN     (OR_PKT_LEN + 500)
#define MAX_NO_OF_SOCK_BUF (5)

typedef struct OrSocketBufT_{
    OrUint8 buf[SOCKET_BUF_LEN];
    OrUint16 bufL;
    struct OrSocketBufT_ *next;
} OrSocketBuf;

typedef OrSocketBuf* OrSockBufList;

/* socket parameters */
typedef struct OrSocket_t{
   int fd; /* file descriptor of the socket */
   OrBool attached;
   OrSockBufList bufList;
   struct OrSocket_t *next;
} OrSocket;

OrInt8 or_run_client_server_test(OrInt *clientFd,
                                             OrCharString *host,
                                             OrHostIdType hIdType);
#endif /*__OR_UTIL_H__*/
