/*
 * FILE:	or_common.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_COMMON__
#define __OR_COMMON__

#include "or_types.h"
#include "or_mem_util.h"

/*-------------------------Common Macros----------------------------*/

/*------------------------------------------------------------------*/
/* Endian conversion */
/*------------------------------------------------------------------*/
#define OR_GET_UINT8_FROM_LITTLE_ENDIAN(ptr) (OrUint8) ((OrUint8 *) (ptr))[0])
#define OR_GET_UINT16_FROM_LITTLE_ENDIAN(ptr) (((OrUint16) ((OrUint8 *) (ptr))[0]) \
                                              | ((OrUint16) ((OrUint8 *) (ptr))[1]) << 8)
#define OR_GET_UINT32_FROM_LITTLE_ENDIAN(ptr) (((OrUint32) ((OrUint8 *) (ptr))[0]) \
                                              | ((OrUint32) ((OrUint8 *) (ptr))[1]) << 8 | \
                                              ((OrUint32) ((OrUint8 *) (ptr))[2]) << 16 \
                                              | ((OrUint32) ((OrUint8 *) (ptr))[3]) << 24)

#define OR_COPY_UINT8_TO_LITTLE_ENDIAN(uint, ptr)   ((OrUint8 *) (ptr))[0] = ((OrUint8)((uint) & 0xFF))
#define OR_COPY_UINT16_TO_LITTLE_ENDIAN(uint, ptr)  ((OrUint8 *) (ptr))[0] = ((OrUint8)((uint) & 0x00FF)); \
                                                    ((OrUint8 *) (ptr))[1] = ((OrUint8) ((uint) >> 8))
#define OR_COPY_UINT32_TO_LITTLE_ENDIAN(uint, ptr)  ((OrUint8 *) (ptr))[0] = ((OrUint8) ((uint) & 0x000000FF)); \
                                        ((OrUint8 *) (ptr))[1] = ((OrUint8) (((uint) >> 8) & 0x000000FF)); \
                                        ((OrUint8 *) (ptr))[2] = ((OrUint8) (((uint) >> 16) & 0x000000FF)); \
                                        ((OrUint8 *) (ptr))[3] = ((OrUint8) (((uint) >> 24) & 0x000000FF))

#define OR_GET_UINT16_FROM_BIG_ENDIAN(ptr) (((OrUint16) ((OrUint8 *) (ptr))[1]) \
                                        | ((OrUint16) ((OrUint8 *) (ptr))[0]) << 8)
#define OR_GET_UINT32_FROM_BIG_ENDIAN(ptr) (((OrUint32) ((OrUint8 *) (ptr))[3]) \
                                            | ((OrUint32) ((OrUint8 *) (ptr))[2]) << 8 | \
                                             ((OrUint32) ((OrUint8 *) (ptr))[1]) << 16 | \
                                             ((OrUint32) ((OrUint8 *) (ptr))[0]) << 24)

#define OR_COPY_UINT16_TO_BIG_ENDIAN(uint, ptr)    ((OrUint8 *) (ptr))[1] = ((OrUint8) ((uint) & 0x00FF)); \
                                                    ((OrUint8 *) (ptr))[0] = ((OrUint8) ((uint) >> 8))
#define OR_COPY_UINT24_TO_BIG_ENDIAN(uint, ptr)    ((OrUint8 *) (ptr))[2] = ((OrUint8) ((uint) & 0x000000FF)); \
                                            ((OrUint8 *) (ptr))[1] = ((OrUint8) (((uint) >> 8) & 0x000000FF)); \
                                            ((OrUint8 *) (ptr))[0] = ((OrUint8) (((uint) >> 16) & 0x000000FF))
#define OR_COPY_UINT32_TO_BIG_ENDIAN(uint, ptr)    ((OrUint8 *) (ptr))[3] = ((OrUint8) ((uint) & 0x000000FF)); \
                                            ((OrUint8 *) (ptr))[2] = ((OrUint8) (((uint) >> 8) & 0x000000FF)); \
                                            ((OrUint8 *) (ptr))[1] = ((OrUint8) (((uint) >> 16) & 0x000000FF)); \
                                            ((OrUint8 *) (ptr))[0] = ((OrUint8) (((uint) >> 24) & 0x000000FF))


#define or_util_add_to_list(head, type, nodex) \
do {                                           \
    type *traversez = head;                    \
    if(traversez == NULL) {                    \
        head = nodex;                          \
    }                                          \
    else {                                     \
        while(traversez->next != NULL) {       \
            traversez = traversez->next;       \
        }                                      \
        traversez->next = nodex;               \
    }                                          \
}while(0)

#define or_util_add_to_list_head(head, type, nodex) \
do {                                                \
    if(head == NULL) {                              \
        head = nodex;                               \
    }                                               \
    else {                                          \
        nodex->next = head;                         \
        head = nodex;                               \
    }                                               \
}while(0)

#define or_util_add_to_mix_pool(head, type, nodex)  \
do {                                                \
    if(head == NULL) {                              \
        head = nodex;                               \
    }                                               \
    else {                                          \
        nodex->mixnext = head;                      \
        head = nodex;                               \
    }                                               \
}while(0)


#define or_util_find_node_in_list(head, type, valueFieldname, value, nodex) \
do {                                                     \
    type *traversez = head;                              \
    while (traversez != NULL) {                          \
        if(traversez->valueFieldname == value) {         \
            break;                                       \
        }                                                \
        traversez = traversez->next;                     \
    }                                                    \
    nodex = traversez;                                   \
}while(0)


#define or_util_remove_node_from_list(head, type, nodex) \
do {                                                     \
    type *traversez =head, *prev = head;                 \
    while (traversez != NULL) {                          \
        if(traversez == nodex) {                         \
            break;                                       \
        }                                                \
        prev     = traversez;                            \
        traversez = traversez->next;                     \
    }                                                    \
    if(traversez != NULL) {                              \
        if(traversez == prev) {                          \
            head = nodex->next;                          \
            or_mem_free(nodex);                          \
        }                                                \
        else {                                           \
            prev->next = nodex->next;                    \
            or_mem_free(nodex);                          \
        }                                                \
    }                                                    \
}while(0)

#define or_util_unlink_node_from_list(head, type, nodex) \
do {                                                     \
    type *traversez =head, *prev = head;                 \
    while (traversez != NULL) {                          \
        if(traversez == nodex) {                         \
            break;                                       \
        }                                                \
        prev     = traversez;                            \
        traversez = traversez->next;                     \
    }                                                    \
    if(traversez != NULL) {                              \
        if(traversez == prev) {                          \
            head = nodex->next;                          \
        }                                                \
        else {                                           \
            prev->next = nodex->next;                    \
        }                                                \
    }                                                    \
}while(0)

#define or_util_remove_from_mixpool(head, type, nodex)   \
do {                                                     \
    type *traversez =head, *prev = head;                 \
    while (traversez != NULL) {                          \
        if(traversez == nodex) {                         \
            break;                                       \
        }                                                \
        prev     = traversez;                            \
        traversez = traversez->mixnext;                  \
    }                                                    \
    if(traversez != NULL) {                              \
        if(traversez == prev) {                          \
            head = nodex->mixnext;                       \
        }                                                \
        else {                                           \
            prev->mixnext = nodex->mixnext;              \
        }                                                \
    }                                                    \
}while(0)



#define or_util_destroy_list(head, type)                \
do {                                                    \
    type *traversez = head, *nodeToDelete = head;       \
    while(traversez != NULL) {                          \
        nodeToDelete = traversez;                       \
        traversez     = traversez->next;                \
        or_mem_free(nodeToDelete);                      \
    }                                                   \
    head = NULL;                                        \
}while(0)

#define OR_CREATE_Q(TYPE, qId)           \
    typedef struct OrQnodeT_##qId {      \
        TYPE  value;                     \
        struct OrQnodeT_##qId *next;     \
    }OrQnode##qId;                       \
                                         \
    typedef struct {                     \
        OrQnode##qId *head;              \
        OrQnode##qId *tail;              \
    }OrQId##qId;                         \
                                         \
    OrQId##qId qId;                      

#define OR_INIT_Q(qId)                   \
    do {                                 \
        qId.head = qId.tail = NULL;      \
    } while(0)

#define OR_IS_Q_EMPTY(qId)  ((qId.head == NULL) && (qId.tail == NULL)) ? TRUE : FALSE

#define OR_Q_PUT(qId, v)                                                        \
do {                                                                            \
    OrQnode##qId *xnode = (OrQnode##qId *) or_mem_alloc(sizeof(OrQnode##qId));  \
    xnode->value        = v;                                                    \
    xnode->next         = NULL;                                                 \
    if(OR_IS_Q_EMPTY(qId)) {                                                    \
        qId.head = qId.tail = xnode;                                            \
    }                                                                           \
    else {                                                                      \
        xnode->next = qId.head;                                                 \
        qId.head   = xnode;                                                     \
    }                                                                           \
}while(0)

#define OR_Q_GET(qId, v)                                        \
do {                                                            \
    if(!OR_IS_Q_EMPTY(qId)) {                                   \
        OrQnode##qId *xnode = qId.head;                         \
        if(qId.head == qId.tail) {                              \
            xnode = qId.head;                                   \
            qId.head = qId.tail = NULL;                         \
        }                                                       \
        else {                                                  \
            while(xnode->next != qId.tail) {xnode = xnode->next;}  \
            qId.tail       = xnode;                             \
            xnode           = xnode->next;                      \
            qId.tail->next = NULL;                              \
        }                                                       \
        v = xnode->value;                                       \
        or_mem_free(xnode);                                     \
    }                                                           \
}while(0)

#define OR_Q_DESTROY(qId)                                       \
do {                                                            \
    if(!OR_IS_Q_EMPTY(qId)) {                                   \
        OrQnode##qId *nodex = NULL, *prev = qId.head;           \
        while(nodex != NULL) {                                  \
            prev = nodex;                                       \
            nodex = nodex->next;                                \
            or_mem_free(prev);                                  \
        }                                                       \
        qId.head = qId.tail = NULL;                             \
    }                                                           \
}while(0)


#define OR_TEST_INT_Q(qId)                                      \
do {                                                            \
    OrQnode##qId *nodex = qId.head;                             \
    if(!OR_IS_Q_EMPTY(qId)) {                                   \
        while(nodex != NULL) {                                  \
            printf("%d ", nodex->value);                        \
            nodex = nodex->next;                                \
        }                                                       \
        printf("\n");                                           \
    }                                                           \
    else {                                                      \
        printf("Empty Q\n");                                    \
    }                                                           \
}while(0)

#define OR_ASSERT(condition, s)                           \
do {                                                      \
    if (condition) {                                      \
        printf("ASSERT: %s!!!", s);                       \
        exit(1);                                          \
    }                                                     \
}while(0)

#define OR_XOR_FORW_BACK_KEY_N_TIMES(data, key, n)        \
do{                                                       \
    OrUint8 i, j;                                         \
    OrUint8 *p = data;                                    \
    for(i = 0; i < n; i++) {                              \
        for(j = 0; j < OR_FORW_BACK_KEY_LENGTH; j++) {    \
            p[j] ^= key[j];                               \
        }                                                 \
        p += OR_FORW_BACK_KEY_LENGTH;                     \
    }                                                     \
}while(0)

#define OR_XOR_KEY_N_TIMES OR_XOR_FORW_BACK_KEY_N_TIMES

#define OR_XOR_FORW_BACK_KEY_N_BYTES(data, key, n)        \
do{                                                       \
    OrUint8 j;                                            \
    OrUint8 *p = data;                                    \
    for(j = 0; j < n; j++) {                              \
        p[j] ^= key[j];                                   \
    }                                                     \
}while(0)

#define OR_XOR_KEY_N_BYTES OR_XOR_FORW_BACK_KEY_N_BYTES

/*---------------------------Common Fn Prototype------------------------------*/
extern OrContext orContext;
extern OrInt or_create_socket_thread(void);
extern OrBool or_sock_write_req(OrInt fd, const OrUint8 *data, OrUint16 dataL);
extern OrBool or_validate_public_key_from_neighbor_table(void);
extern OrBool or_get_saved_public_private_key(void);
extern OrBool or_validate_public_key_from_neighbor_table(void);
extern OrBool or_validate_role_from_neighbor_table(void);
extern OrBool or_get_member_id_from__neighbor_table(void);
extern OrBool or_get_neighbor_dh_keys(void);
extern OrBool or_create_or_pkt(OrUint8 *linkKey,
                               OrUint32 cid,
                               OrUint8 cmd,
                               OrUint8 type,
                               OrUint8 *data,
                               OrUint16 dataLength,
                               OrUint8 mac[OR_MAC_SIZE],
                               OrUint8 **orPkt);
extern OrBool or_parse_incoming_data(const OrUint8 *data,
                            OrUint16 dataL,
                            OrIncmingDataTuple *iTuple);
extern OrInt8 or_connect_to_remote_server(OrInt *clientFd,
                                OrCharString *host,
                                OrUint16 port,
                                OrHostIdType hIdType);
extern OrBool or_is_replayed_onion(OrIncmingDataTuple *iTuple,
                            OrOnionList *unExpdOnionListH,
                            OrOnionList *expdOnionListH,
                            OrMutexHandle unExpdOnionListLock,
                            OrMutexHandle expdOnionListLock);

#endif /* __OR_COMMON_H__ */
