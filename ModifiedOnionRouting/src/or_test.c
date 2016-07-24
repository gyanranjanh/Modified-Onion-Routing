/*
 * FILE:	or_test.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_types.h"
#include "or_log.h"
#include "or_util.h"
#include "or_common.h"

#define BUFFLEN 2048

static OrInt maxfd = -1;
static fd_set rset, wset;

/* Client-Server Test */
OrInt8 or_run_client_server_test(OrInt *clientFd,
                                OrCharString *host,
                                OrHostIdType hIdType)
{
    struct hostent *hp = NULL;
    struct sockaddr_in server;
    OrInt cFd = -1, result = -1;
    OrCharString buffer[BUFFLEN];
    OrCharString *buf = buffer;
    OrInt flags;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* Create a new stream socket */
    if((cFd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Socket create failed !!!!",
                                                   __FUNCTION__, __LINE__);
        goto OUT;
    }

    flags = fcntl(cFd, F_GETFL, 0);
    OR_ASSERT((flags == -1), "fctrl failed\n");
    fcntl(cFd, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(cFd, F_GETFL, 0);

    OR_ASSERT(((flags & O_NONBLOCK) != O_NONBLOCK), "socket not non-blocking\n");

    /* Initialize socket address */
    or_mem_zero(&server, sizeof(struct sockaddr_in));

    server.sin_family      = AF_INET;
    server.sin_port        = htons(3001);

    if(hIdType == OR_HOST_NAME)
    {
        /* Get host address */
        if((hp = gethostbyname(host)) == NULL)
        {
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Can;t get server's address!!!!",
                                                       __FUNCTION__, __LINE__);
            close(cFd);
            goto OUT;
        }

        /* bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length); */
        or_mem_copy(&server.sin_addr, hp->h_addr, hp->h_length);
    }
    else
    {
        server.sin_addr.s_addr = inet_addr(host);
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Connecting to: %d.%d.%d.%d",
                             __FUNCTION__, __LINE__,
                            (OrInt)(server.sin_addr.s_addr & 0xFF),
                            (OrInt)((server.sin_addr.s_addr & 0xFF00)>>8),
                            (OrInt)((server.sin_addr.s_addr & 0xFF0000)>>16),
                            (OrInt)((server.sin_addr.s_addr & 0xFF000000)>>24));


    /* Connect to server */
    if(connect(cFd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) == -1)
    {
        if (errno != EINPROGRESS) {
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Connect failed!!!! %s",
                                               __FUNCTION__, __LINE__, strerror(errno));
            close(cFd);
            goto OUT;
        }
        else {
            OrInt n, error;
            FD_ZERO(&rset);
            FD_ZERO(&wset);
            maxfd = -1;
            FD_SET(cFd, &rset);
            FD_SET(cFd, &wset);
            if(cFd > maxfd) {
                maxfd = cFd;
            }
            n = select(maxfd+1, &rset, &wset, NULL, NULL);
            if ((FD_ISSET(cFd, &rset) || FD_ISSET(cFd, &wset))) {
                n = sizeof(error);
                if (getsockopt(cFd, SOL_SOCKET, SO_ERROR, &error, &n) < 0 ||
                error != 0) {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Connect failed!!!! %s",
                                                       __FUNCTION__, __LINE__, strerror(errno));
                    close(cFd);
                    goto OUT;
                }
            }
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Connected to: %d.%d.%d.%d",
                             __FUNCTION__, __LINE__,
                            (OrInt)(server.sin_addr.s_addr & 0xFF),
                            (OrInt)((server.sin_addr.s_addr & 0xFF00)>>8),
                            (OrInt)((server.sin_addr.s_addr & 0xFF0000)>>16),
                            (OrInt)((server.sin_addr.s_addr & 0xFF000000)>>24));


    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Sending data",
                                           __FUNCTION__, __LINE__);

    buf = "Hello Server! Greeting from client";

    write(cFd, buf, strlen(buf));

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Client sent greetings!!!!",
                                       __FUNCTION__, __LINE__);
    while(1);

OUT:
    *clientFd = cFd;
    return result;
}
