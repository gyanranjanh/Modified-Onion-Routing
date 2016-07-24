/*
 * FILE:	or_util.c
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
#include "or_mem_util.h"

#define MAX_INCOMING_CONNECT_REQ    (5)

/*----------------------Local Variables--------------------------*/
static OrThread or_listen_socket_thread = 0;
static OrThread        or_reader_thread = 0;
static OrInt                  controlFds[2];
static OrSocket          *socketList = NULL;


/*----------------------Local Fn Declaration---------------------*/
static void or_get_fd_set(fd_set *fdSet, OrInt*lastFd);
static OrUint8 or_add_client_socket(OrInt newFd);
static void or_remove_client_socket(OrInt fd);
static OrBool or_find_client_socket(OrInt fd, OrSocket **sNode);
static OrInt or_create_socket(struct sockaddr_in *addr);
static void *or_listen_socket_thred_fn(void *thread_param);
static void *or_server_receive_thread(void *thread_param);

/*-----------------------Local Fn Definition---------------------*/

static void or_get_fd_set(fd_set *fdSet, OrInt*lastFd)
{
    OrSocket *node = socketList;

    /* OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %i)> node = %x", __FUNCTION__, __LINE__, 
    node); */

    *lastFd = -1;

    while(node != NULL)
    {
        /* Max fds that can be set = FD_SETSIZE */
        FD_SET(node->fd, fdSet);
        if(node->fd > *lastFd)
        {
            *lastFd = node->fd;
        }
        node = node->next;
        /* OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %i)> node = %x lastfd = %d", 
                                 __FUNCTION__, __LINE__, node, *lastFd); */
    }

}

/*
 * or_add_client_socket:
 * Adds new socket to list 
 * returns no of sockets in list
 */
static OrUint8 or_add_client_socket(OrInt newFd)
{
    OrUint8 count = 1;
    OrSocket *node = socketList, *newSocket = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    newSocket = (OrSocket *)or_mem_alloc(sizeof(OrSocket));
    or_mem_set(newSocket, 0x00, (sizeof(OrSocket)));

    if(newSocket == NULL)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Memory Aoocation failed",
                                                   __FUNCTION__, __LINE__);
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> No fail safe...exiting",
                                                    __FUNCTION__, __LINE__);
        exit(1);
    }

    newSocket->fd       = newFd;
    newSocket->attached = FALSE;
    newSocket->next     = NULL;

    if(node == NULL)
    {
        /* First Socket */
        socketList = newSocket;
    }
    else
    {
        while(node->next != NULL)
        {
            count++;
            node = node->next;
        }

        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Inserting node at tail",
                                                    __FUNCTION__, __LINE__);
        node->next = newSocket;
        count++;
    }

    return count;
}

/*
 * or_remove_client_socket:
 * Remove socket corresponding to 'fd'from socket list 
 * returns nothing
 */
static void or_remove_client_socket(OrInt fd)
{
    OrSocket *node = socketList, *prev = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);


    while(node && node->fd != fd)
    {
        prev = node;
        node = node->next;
    }

    if(node != NULL)
    {
        if(prev == NULL)
        {
            socketList = NULL;
        }
        else
        {
            prev->next = node->next;
        }

        or_mem_free(node);
        close(fd);
    }
}

static OrBool or_find_client_socket(OrInt fd, OrSocket **sNode)
{
    OrSocket *node = socketList, *prev = NULL;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    while(node && node->fd != fd)
    {
        prev = node;
        node = node->next;
    }

    if(node != NULL)
    {
        *sNode = node;
        result = TRUE;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<",
                                            __FUNCTION__, __LINE__, result);

    return result;
}

/*
 * or_create_socket:
 * Creates new socket with address 'addr' 
 * returns new socket fd
 */
static OrInt or_create_socket(struct sockaddr_in *addr)
{
    OrInt fd, newfd, port;
    OrInt result = -1;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* Create a stream socket */
    if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Socket create failed !!!!",
                                                   __FUNCTION__, __LINE__);
        goto OUT;
    }

    /* Bind the address to the socket */
    if(bind(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == -1)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Socket bind failed !!!!",
                                                    __FUNCTION__, __LINE__);
        close(fd);
        goto OUT;
    }

    /* Socket create successful. Return fd */
    result = fd;

OUT:
    return result;
}

/*
 * or_listen_socket_thred_fn:
 * Server socket thread fn 
 * returns 'TBD'
 */
static void * or_listen_socket_thred_fn(void *thread_param)
{
    struct sockaddr_in srvr_addr, client_addr;
    OrInt32 result;
    OrInt server_fd, new_fd;
    OrUint32 retryCount = 16; 
    socklen_t cl_length;

    UNUSED(thread_param);

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    controlFds[0] = controlFds[1] = 0;

    /* Initialize server address */
    or_mem_zero(&srvr_addr, sizeof(struct sockaddr_in));

    srvr_addr.sin_family      = AF_INET;
    srvr_addr.sin_port        = htons(orContext.port);
    srvr_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* Create a new server socket */
    server_fd = or_create_socket(&srvr_addr);
    if(server_fd < 0)
    {
        goto OUT;
    }

    /* Listen to incoming connections */
    if(listen(server_fd, MAX_INCOMING_CONNECT_REQ) == -1)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Listen failed!!!!", __FUNCTION__, __LINE__);
        close(server_fd);
        goto OUT;
    }

    /* Accept incoming connections */
    while(TRUE && retryCount)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Ready for next incoming connection!!!!", 
                                                                    __FUNCTION__, __LINE__);
        cl_length = sizeof(struct sockaddr_in);
        new_fd = accept(server_fd, (struct sockaddr *)&client_addr, &cl_length);

        if(new_fd < 0)
        {
            retryCount--;
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> socket accept failed %d %s", 
                                __FUNCTION__, __LINE__, new_fd, strerror(errno));
        }
        else
        {
            /* Add new socket fd to client socket list */
            if(or_add_client_socket(new_fd) == 1)
            {
                /* This is the first socket. Start reveiver thread */
                OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %d)> Starting rx thread",
                                                                __FUNCTION__, __LINE__);
                result = CREATE_THREAD(&or_reader_thread, NULL, 
                                                or_server_receive_thread, NULL);
                if(result!= 0)
                {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> rx thread create failed %d %s",
                                    __FUNCTION__, __LINE__, result, strerror(errno));
                } 
            }
            else
            {
                /* Signal rx thread about new socket */
                send(controlFds[1],"NEWFD",5, 0);
            }
        }
    } /* end while */

    close(server_fd);
OUT:
    return NULL;
}

static void * or_server_receive_thread(void *thread_param)
{
    OrInt  result;
    fd_set readFdSet, writeFdSet, eFdSet;
    OrInt  lastFd, removeFd = 0;
    OrSocket *node = NULL;
    OrUint8 buffer[2048];
    struct timeval timeout;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);


    UNUSED(thread_param);

    /* Create control Fds that will be used to unblock select when a new 
       connection is created */
    result = socketpair(AF_LOCAL, SOCK_STREAM, 0, controlFds);
    if(result != 0)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %i)socket-pair failed %d %s>",
                                      __FUNCTION__, __LINE__, result, strerror(errno));
        goto OUT;
    }

    while(TRUE)
    {
        node = socketList;

        /* Initialize read and excetion fd set */
        FD_ZERO(&readFdSet);
        FD_ZERO(&writeFdSet);
        FD_ZERO(&eFdSet);

        /* Get read, write and excetion fd set */
        or_get_fd_set(&readFdSet, &lastFd);
        or_get_fd_set(&writeFdSet, &lastFd);
        or_get_fd_set(&eFdSet, &lastFd);

        if(lastFd == -1)
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> Exiting server side "
                                            "reader thread as no more fds.", 
                                                    __FUNCTION__, __LINE__);
            break;
        }

        FD_SET(controlFds[0], &readFdSet);
        if(controlFds[0] > lastFd)
        {
            lastFd = controlFds[0];
        }

        /* use select to wait for data */
        /* OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> waiting for data", 
                                                __FUNCTION__, __LINE__); */

        result = select(lastFd + 1, &readFdSet, &writeFdSet, &eFdSet, NULL);

        /* OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> select unblocked", 
                                                __FUNCTION__, __LINE__); */

        if(result > 0)
        {
            /* Check if control FD is set */
            if(FD_ISSET(controlFds[0], &readFdSet))
            {
                /* Read and ignore data 
                 * Data is written on control FD to unblock select and add 
                   new FD to list*/
                result = recv(controlFds[0], buffer, sizeof(buffer) - 1, 0); 
                buffer[result] = '\0';
                OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %i)> controlFD = %s", 
                                    __FUNCTION__, __LINE__, buffer, result);
            }

            while(node != NULL)
            {
                /* OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %i)> node = %x, fd = %d", 
                                         __FUNCTION__, __LINE__, node, 
                                         node->fd); */

                removeFd = 0;
                if(FD_ISSET(node->fd, &readFdSet))
                {
                    /* Read the data */
                    result = recv(node->fd, buffer, sizeof(buffer), 0);

                    if(result <= 0)
                    {
                        removeFd = node->fd;
                        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %i)> "
                            "0 bytes read in fd = %d. Removing.", 
                                    __FUNCTION__, __LINE__, node->fd);
                    }
                    else
                    {
                        buffer[result] = '\0';
#ifdef OR_CLIENT_SERVER_TEST
                        OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> data = %s", 
                                                    __FUNCTION__, __LINE__, buffer);
#endif

                        /* Pass the data to respective handler */
                         switch(orContext.role)
                        {
                            case OR_SENDER:
                            {
                                OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> "
                                                          "unhandled in case "
                                                          "OR_SENDER", 
                                                          __FUNCTION__, __LINE__);
                            }
                            break;
                            case OR_RECEIVER:
                            {
                                OrUint8  m = 0, k = 0;
                                OrUint16 n = 0;

                                m = result / OR_PKT_LEN;
                                n = result % OR_PKT_LEN;

                                while(m > 0) {
                                    or_exit_funnel_handler(node->fd,
                                        buffer + k * OR_PKT_LEN, OR_PKT_LEN);
                                    k++;
                                    m--;
                                }

                                /* TBD: Ignore the odd bytes for now */
                                UNUSED(n);
#if 0
                                if(n > 0) {
                                    or_exit_funnel_handler(node->fd,
                                        buffer + k * OR_PKT_LEN, n);
                                }
#endif
                            }
                            break;
                            case OR_ROUTER:
                            {
                                OrUint8  m = 0, k = 0;
                                OrUint16 n = 0;

                                m = result / OR_PKT_LEN;
                                n = result % OR_PKT_LEN;

                                while(m > 0) {
                                    or_router_handler(node->fd,
                                        buffer + k * OR_PKT_LEN, OR_PKT_LEN);
                                    k++;
                                    m--;
                                }

                                /* TBD: Ignore the odd bytes for now */
                                UNUSED(n);
#if 0
                                if(n > 0) {
                                    or_router_handler(node->fd,
                                        buffer + k * OR_PKT_LEN, n);
                                }
#endif
                            }
                            break;
                            default:
                            {
                                buffer[result] = 0;
                                OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %i)> data = %s", 
                                                            __FUNCTION__, __LINE__, buffer);
                            }
                        }
                    }
                }

                if(FD_ISSET(node->fd, &writeFdSet))
                {
                    //OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "For write\n");
                    if(node->bufList != NULL) {
                        OrSocketBuf *pnode = node->bufList;
                        OrInt nbytes = 0;
                        /* find if this socket has any data pending to be sent */
                        while(pnode->next != NULL) {
                            pnode = pnode->next;
                        }
                        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "writing to fd: "
                                                            "%d\n", node->fd);
                        nbytes = write(node->fd, pnode->buf, pnode->bufL);
                        pnode->buf[pnode->bufL] = '\0';
                        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, 
                                            "wrote: %d bytes\n", pnode->bufL);
                        if(nbytes > 0) {
                            OR_ASSERT((nbytes > pnode->bufL),
                                "or_sever_recv_thrd> Invalid write\n");
                            if(nbytes < pnode->bufL) {
                                pnode->bufL -= nbytes;
                                or_mem_copy(pnode->buf, 
                                            &pnode->buf[nbytes], pnode->bufL);
                            }
                            else {
                                or_util_remove_node_from_list(node->bufList, 
                                                            OrSocketBuf, pnode);
                            }
                        }
                    }
                    else {
                        //OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "No Data to write\n");
                    }
                }

                if(FD_ISSET(node->fd, &eFdSet))
                {
                    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> exception fd = %d", 
                                    __FUNCTION__, __LINE__, node->fd);
                    removeFd = node->fd;
                }

                node = node->next;
                if(removeFd)
                {
                    or_remove_client_socket(removeFd);
                } 
            }
        }
    } /* end while */

OUT:
    return NULL;
}
/*----------------------Global Fn Definition---------------------*/
/*
 * or_create_socket_thread:
 * Creates server socket thread 
 * returns thread id
 */
OrInt or_create_socket_thread()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    return CREATE_THREAD(&or_listen_socket_thread, NULL, or_listen_socket_thred_fn, NULL);
}

OrBool or_sock_write_req(OrInt fd, const OrUint8 *data, OrUint16 dataL)
{
    OrBool result = FALSE;
    OrSocketBuf *node = NULL;
    OrSocket   *sNode = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    /* find socket node */
    if(or_find_client_socket(fd, &sNode)) {
        OR_ASSERT((sNode == NULL), 
                "or_sock_write_req> sNode is NULL\n");
        if(data != NULL && dataL != 0) {
            if(dataL <= SOCKET_BUF_LEN) {
                node = (OrSocketBuf *)or_mem_alloc(sizeof(OrSocketBuf));
                OR_ASSERT((node == NULL), "or_sock_write_req> mem alloc failed\n");
                or_mem_set(node, 0x00, sizeof(OrSocketBuf));

                or_mem_copy(node->buf, (void *)data, dataL);
                node->bufL = dataL;
                or_util_add_to_list_head(sNode->bufList, OrSocketBuf, node);
                result = TRUE;
            }
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %d <<",
                                    __FUNCTION__, __LINE__, result);

    return result;
}