/*
 * FILE:	or_onion_proxy.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_util.h"
#include "or_common.h"
#include "or_log.h"
#include "or_time.h"
#include "or_onion_proxy.h"
#include "or_security_module.h"

/*---------------------------Local Type Defn-------------------------------*/
typedef struct OrSrcPoolT_{
    OrUint8              src;
    //OrRoute           routes;
    struct OrSrcPoolT_ *next;
} OrSrcPool;

/*----------------------------Local Variables------------------------------*/
static OrOnionProxySessionEntry               *orOnionProxySesnTable = NULL;
static OrSrcPool                                     *orKnownSrcPool = NULL;
static OrMemberNeighborTablePairPool *orMmemberNeighborTablePairPool = NULL;
static OrMutexHandle                                orSesnDataHLock = NULL;

OR_CREATE_Q(OrUint8, orAvlblSesnId);
OR_CREATE_Q(OrUint8, orAvlblVcId);

/*---------------------------Local Macro Defn------------------------------*/
#define or_onion_proxy_find_neighbor_table_of_member(memberId, membrNebrTablePair) \
do { \
    OrMemberNeighborTablePairPool *node = orMmemberNeighborTablePairPool;          \
    while(node != NULL) {                                                          \
        if(node->memberNbrTablePair.memberId == memberId) {                        \
            break;                                                                 \
        }                                                                          \
        node = node->next;                                                         \
    }                                                                              \
    if(node != NULL) {                                                             \
        membrNebrTablePair = &node->memberNbrTablePair;                            \
    } \
}while(0)

#define EXIT_PROG   exit(1)
/*----------------------------Local Fn Declareation------------------------*/
static OrBool or_onion_proxy_is_known_dest(OrUint8 memberId);
static void or_onion_proxy_add_dest_to_known_dest_pool(OrUint8 memberId);
static OrBool or_onion_proxy_does_member_neighbor_table_pair_exist(OrUint32 memberId);
static OrBool or_onion_proxy_does_session_exist(OrOnionProxySessionEntry *reqEntry);
static OrBool or_onion_proxy_is_active_session(OrUint32 memberId, OrUint8 sessionId,
                                               OrOnionProxySessionEntry **orPxySesn);
static OrBool or_onion_proxy_is_dest_end_device(OrMemberNeighborTablePair *memberNbrTablePair,
                                                OrDestAddress dest, OrUint8 *destIdx);
static OrUint8 or_onion_proxy_sort_nbr_table(OrNeighborTable *nbrTable);
static OrBool or_onion_proxy_create_onion(OrUint8 memberId, OrDestAddress dest,
                                                OrOnionProxySessionEntry *orSesnInfo);
static void or_onion_proxy_encrypt_pkt(const OrOnionProxySessionEntry *orPxySesn,
                                       OrUint8 *data, OrUint16 dataLen);
static void or_onion_proxy_decrypt_pkt(const OrOnionProxySessionEntry *orPxySesn,
                                       OrUint8 *data, OrUint16 dataLen);
static void *or_onion_proxy_rcv_thread(void *thread_param);
static void *or_onion_proxy_snd_thread(void *thread_param);

/*---------------------------Local Fn Defn-----------------------------*/
static OrBool or_onion_proxy_is_known_dest(OrUint8 memberId)
{
    OrSrcPool *node  = orKnownSrcPool;
    OrBool    result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    while(node != NULL) {
        if(node->src == memberId) {
            break;
        }
        node = node->next;
    }

    if(node != NULL){
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Src is known", __FUNCTION__, __LINE__);
        result = TRUE;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

static void or_onion_proxy_add_dest_to_known_dest_pool(OrUint8 memberId)
{
    if(!or_onion_proxy_is_known_dest(memberId)) {
        OrSrcPool *node = NULL;

        node = (OrSrcPool *) or_mem_alloc(sizeof(OrSrcPool));

        if(node != NULL) {
            node->src  = memberId;
            node->next = NULL;
            or_util_add_to_list(orKnownSrcPool, OrSrcPool, node);
        }
        else {
            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> memory allocation failed", 
                                                    __FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Destination alredy exists "
                                    "in destination pool", __FUNCTION__, __LINE__);
    }
}

static OrBool or_onion_proxy_does_member_neighbor_table_pair_exist(OrUint32 memberId)
{
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    OrMemberNeighborTablePairPool *node = orMmemberNeighborTablePairPool;

    while(node != NULL){
        if(node->memberNbrTablePair.memberId == memberId) {
            break;
        }
        node = node->next;
    }

    if(node != NULL){
        result = TRUE;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                    __FUNCTION__, __LINE__, result);

    return result;
}

static OrBool or_onion_proxy_does_session_exist(OrOnionProxySessionEntry *reqEntry)
{
    OrOnionProxySessionEntry *node = orOnionProxySesnTable;
    OrBool                  result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    while(node != NULL) {
        if((node->memberId == reqEntry->memberId)
           && (!or_mem_cmp(node->orSesnProxyTriplet.dest.ip, 
               reqEntry->orSesnProxyTriplet.dest.ip, sizeof(OR_IP_ADDRESS_LENGTH)))
           && (node->orSesnProxyTriplet.proto == 
                                        reqEntry->orSesnProxyTriplet.proto)
           && (node->payLoadType == reqEntry->payLoadType)
           && (node->appDataIndFn == reqEntry->appDataIndFn)){
           break;
        }
        node = node->next;
    }

    if(node != NULL) {
        reqEntry->orSesnProxyTriplet.sessionId = 
                        node->orSesnProxyTriplet.sessionId;
        result = TRUE;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

static OrBool or_onion_proxy_is_active_session(OrUint32 memberId,
                                               OrUint8 sessionId,
                                               OrOnionProxySessionEntry **orPxySesn)
{
    OrOnionProxySessionEntry *node = orOnionProxySesnTable;
    OrBool                  result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> m: %u s: %u>>",
                        __FUNCTION__, __LINE__, memberId, sessionId);

    while(node != NULL) {
        if((node->memberId == memberId)
           && (node->orSesnProxyTriplet.sessionId
           == sessionId)){
           break;
        }
        /*printf("memId: %u sesId: %u\n",
            node->memberId, node->orSesnProxyTriplet.sessionId);*/
        node = node->next;
    }

    if(node != NULL) {
        *orPxySesn = node;
        result = TRUE;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}


static OrBool or_onion_proxy_is_dest_end_device(OrMemberNeighborTablePair *memberNbrTablePair,
                                                OrDestAddress dest,
                                                OrUint8 *destIdx) {
    OrUint8 itr;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    for(itr = 0; 
        itr < memberNbrTablePair->neighborTable->noOfEntriesInNeighborTable;
        itr++) {
        if(
            (!or_mem_cmp(memberNbrTablePair->neighborTable->orNeighbor[itr].ip,
            dest.ip, OR_IP_ADDRESS_LENGTH))
            && memberNbrTablePair->neighborTable->orNeighbor[itr].port == dest.port
          ) {
              break;
          }
    }

    if(itr != memberNbrTablePair->neighborTable->noOfEntriesInNeighborTable) {
        if(memberNbrTablePair->neighborTable->orNeighbor[itr].deviceType
            ==  OR_END_DEVICE_T) {
            result = TRUE;
            *destIdx = itr;
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Destination found. "
                            "Its member id is (%u).", 
                            __FUNCTION__, __LINE__,
            memberNbrTablePair->neighborTable->orNeighbor[itr].memberId);
        }
        else {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                       "Destination is not end device."
                                        ,__FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                               "Destination not found in neighbor table"
                                                  ,__FUNCTION__, __LINE__);
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

static OrUint8 or_onion_proxy_sort_nbr_table(OrNeighborTable *nbrTable)
{
    OrUint8 itr = 0, k = 0, j = 0, i = 0;
    OrUint8 *p = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> no of "
                               "members in nbr table %u", 
                               __FUNCTION__, __LINE__, nbrTable->noOfEntriesInNeighborTable);


    if(nbrTable != NULL) {
        if(nbrTable->noOfEntriesInNeighborTable > 1) {
            p = (OrUint8 *) or_mem_alloc(nbrTable->noOfEntriesInNeighborTable);

            OR_ASSERT((p == NULL), "or_onion_proxy_sort_nbr_table> mem alloc failed\n");

            or_mem_set(p, OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1,
                                    (nbrTable->noOfEntriesInNeighborTable));
            for(itr = 0; itr < nbrTable->noOfEntriesInNeighborTable; itr++) {
                if(nbrTable->orNeighbor[itr].deviceType == OR_ROUTER_T) {
                    p[k++] = itr;
                }
            }

            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> No of routers %u",
                                        __FUNCTION__, __LINE__, k);

            if(k != 0) {
                for(i = 0; i < (k - 1); i++) {
                    for(j = 0; j < (k - 1); j++) {
                        if(nbrTable->orNeighbor[p[j]].memberId
                            > nbrTable->orNeighbor[p[j + 1]].memberId) {
                            OrUint8 temp = p[j];
                            p[j]         = p[j + 1];
                            p[j + 1]     = temp;
                        }
                    }
                }

                for(i = 0; i < k/2; i++) {
                    OrNeighbor temp  = nbrTable->orNeighbor[p[k - 1 - i]];
                    nbrTable->orNeighbor[p[k - 1 - i]] = nbrTable->orNeighbor[p[i]];
                    nbrTable->orNeighbor[p[i]]         = temp;
                }

                for(i = 0; i < k; i++) {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> sorted routers "
                                "are with memberId: %u at idx: %u",
                                __FUNCTION__, __LINE__,
                                nbrTable->orNeighbor[p[i]].memberId, p[i]);
                }
            }
            or_mem_free(p);
        }
        else {
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>"
                                    "Not enough entries in neighbour table"
                                    ,__FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> nbrTable is NULL!!!",
                                                    __FUNCTION__, __LINE__);
    }

    return k;
}

static OrBool or_onion_proxy_does_dest_exist_in_nbr_table(OrDestAddress dest,
                                                          OrNeighborTable *nbrTable)
{
    OrUint8 k = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    if(nbrTable != NULL) {
        for(; k < nbrTable->noOfEntriesInNeighborTable; k++) {
            if(!(or_mem_cmp(nbrTable->orNeighbor[k].ip, dest.ip, OR_IP_ADDRESS_LENGTH))
                && (nbrTable->orNeighbor[k].port == dest.port)){
                break;
            }
        }
        if(k != nbrTable->noOfEntriesInNeighborTable) {
            result = TRUE;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                    __FUNCTION__, __LINE__, result);

    return result;
}

static OrBool or_onion_proxy_create_onion(OrUint8 memberId,
                                          OrDestAddress dest,
                                          OrOnionProxySessionEntry *orSesnInfo)
{
    OrMemberNeighborTablePair *memberNbrTablePair = NULL;
    OrBool       result = FALSE,    isFirstRouter = TRUE;
    OrUint8 k = 0, j = 0, destIdx;
    OrRoute route;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    if(orSesnInfo != NULL) {

        or_mem_set(&route, 0x00, sizeof(OrRoute));

        /* retrieve the neighbor table for 'memberId'*/
        or_onion_proxy_find_neighbor_table_of_member(memberId, memberNbrTablePair);

        if(memberNbrTablePair != NULL) {
            OR_ASSERT((memberNbrTablePair->memberId != memberId), 
                                   "or_onion_proxy_create_onion > Invalid neighbor table");

            /* dest must exist in neighbor table */
            if(or_onion_proxy_does_dest_exist_in_nbr_table(dest,
                                memberNbrTablePair->neighborTable)) {
                /* Proceed only if 'dest' is an end device */
                if(or_onion_proxy_is_dest_end_device(memberNbrTablePair, dest, &destIdx)) {
                    /* Create onion making dest as the last node in route */
                    /* Sort neighbor table according to router's increasing member id */
                    OrUint8 noOfRouters = or_onion_proxy_sort_nbr_table(memberNbrTablePair->neighborTable);

                    if(noOfRouters != 0) {
                        route.memberId  = memberId;
                        route.destAddr  = dest;

                        /* add routers to route */
                        while(k < memberNbrTablePair->neighborTable->noOfEntriesInNeighborTable) {
                            if(memberNbrTablePair->neighborTable->orNeighbor[k].deviceType
                                == OR_ROUTER_T) {
                                OrNodeInfo *node = NULL;
                                OrNeighbor *nbr  = &memberNbrTablePair->neighborTable->orNeighbor[k];

                                node = (OrNodeInfo *) or_mem_alloc(sizeof(OrNodeInfo));

                                OR_ASSERT((node == NULL), "or_onion_proxy_create_onion> mem alloc failed\n");

                                /* node's member id */
                                node->memberId = nbr->memberId;
                                /* fill layer info */
                                /* onion exp time  */
                                node->layerInfo.expTime = OR_TYPICAL_EXP_TIME;
                                /* node's backF & forwF */
                                node->layerInfo.backF   = OR_SIMPLE_ENCRYPTION;
                                node->layerInfo.forwF   = OR_SIMPLE_ENCRYPTION;
                                or_mem_copy(node->orDhSecret,
                                    nbr->orDhSecret, OR_DH_SECRET_LENGTH);
                                node->next     = NULL;

                                /* get hash string from security module to send as 
                                 * key */
                                or_get_hash_string(node->layerInfo.orBackFkey);
                                or_get_hash_string(node->layerInfo.orForwFkey);

                                /* find the next router */
                                for(j = k+1; 
                                j < memberNbrTablePair->neighborTable->noOfEntriesInNeighborTable;
                                j++) {
                                    if(memberNbrTablePair->neighborTable->orNeighbor[k].deviceType
                                    == OR_ROUTER_T) {
                                        break;
                                    }//end if
                                }//end for
                                if(j != memberNbrTablePair->neighborTable->noOfEntriesInNeighborTable) {
                                    node->layerInfo.nextmemberId = 
                                        memberNbrTablePair->neighborTable->orNeighbor[j].memberId;
                                }
                                else {
                                    /* no more router. next node is 'dest' */
                                    node->layerInfo.nextmemberId = 
                                        memberNbrTablePair->neighborTable->orNeighbor[destIdx].memberId;
                                }

                                if(route.routeHead == NULL) {
                                    route.routeHead = node;
                                }
                                else {
                                    OrNodeInfo *pnode = route.routeHead;
                                    while(pnode->next != NULL) {pnode = pnode->next;}
                                    pnode->next = node;
                                }
                                route.routeLen++;
                                if(isFirstRouter == TRUE) {
                                    or_mem_copy(route.nextHopAddr.ip, nbr->ip, 
                                                                OR_IP_ADDRESS_LENGTH);
                                    route.nextHopAddr.port = nbr->port;
                                    isFirstRouter = FALSE;
                                }
                            }//end if
                            k++;
                        }//end while

                        /* add destination to route */
                        do {
                            OrNodeInfo *node = NULL;
                            OrNeighbor *nbr  = 
                                    &memberNbrTablePair->neighborTable->orNeighbor[destIdx];

                            node = (OrNodeInfo *) or_mem_alloc(sizeof(OrNodeInfo));

                            OR_ASSERT((node == NULL), "or_onion_proxy_create_onion> mem alloc failed\n");

                            /* node's member id */
                            node->memberId = nbr->memberId;
                            /* fill layer info */
                            /* onion exp time  */
                            node->layerInfo.expTime = OR_TYPICAL_EXP_TIME;
                            /* node's backF & forwF */
                            node->layerInfo.backF   = OR_SIMPLE_ENCRYPTION;
                            node->layerInfo.forwF   = OR_SIMPLE_ENCRYPTION;
                            or_mem_copy(node->orDhSecret,
                                    nbr->orDhSecret, OR_DH_SECRET_LENGTH);
                            node->next = NULL;

                            /* get hash string from security module to send as 
                             * key */
                            or_get_hash_string(node->layerInfo.orBackFkey);
                            or_get_hash_string(node->layerInfo.orForwFkey);

                            /* next member is NULL */
                            node->layerInfo.nextmemberId = OR_INVALID_MEMBER_ID;

                            OR_ASSERT((route.routeHead == NULL), 
                                "or_onion_proxy_create_onion> FATAL ERROR while "
                                "creating onion route\n");

                            OrNodeInfo *pnode = route.routeHead;
                            while(pnode->next != NULL) {pnode = pnode->next;}
                            pnode->next = node;
                            route.routeLen++;
                        }while(0);
                    }
                    else {
                        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Routers not "
                                        "found in neighbor table in path to dest"
                                                            ,__FUNCTION__, __LINE__);
                    }
                }
                else {
                    OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Dest is not an end "
                                        "device in nbr table", __FUNCTION__, __LINE__);
                }
            }
            else {
                OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Dest does not exist " 
                                    "in nbr table member", __FUNCTION__, __LINE__);
            }
        }
        else {
            OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> No neighbor table found "
                                    "for member %u", __FUNCTION__, __LINE__, memberId);
        }

        /*
        Each layer of onion
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        + challenge(9) + Back F(1) + Forw F(1) + Next MemberId(2) +
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        +                       Back F Key(16)                    +
        +                       Forw F Key(16)                    +
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        +                         Exp Time(4)                     +
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        total length 49 bytes
        */

        if(route.routeHead != NULL && route.routeLen > 1) {
            /* Route head is the next hop. This the point where
             * link encryption for this link of Onion Proxy
             * decided. Copy it to link-key */
            OrUint8 z;
            for(z = 0; z < orContext.neigborTable.noOfEntriesInNeighborTable; 
            z++) {
                if(orContext.neigborTable.orNeighbor[z].memberId ==
                    route.routeHead->memberId)
                {
                    or_mem_copy(route.linkKey,
                        orContext.neigborTable.orNeighbor[z].orDhSecret, OR_DH_SECRET_LENGTH);
                    break;
                }
                OR_ASSERT((z == orContext.neigborTable.noOfEntriesInNeighborTable),
                              "or_onio_proxy_create_onion> link key not found\n");
            }
            do {
                OrUint8 *orFrame = NULL;
                OrUint8   *onion = NULL;
                OrNodeInfo *node = route.routeHead;
                /* Now we have a route. Create onion */
                OR_ASSERT((route.routeLen * OR_ONION_LAYER_LEN > OR_MSS),
                                            "route doesn't fit in payload\n");

                OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Creating onion. "
                        "(route-length %u)", __FUNCTION__, __LINE__, route.routeLen);

                onion = (OrUint8 *) or_mem_alloc(route.routeLen * OR_ONION_LAYER_LEN);

                OR_ASSERT((onion == NULL), "or_onion_proxy_create_onion> mem alloc failed\n");
                OR_ASSERT((node == NULL), 
                    "or_onion_proxy_create_onion> FATAL ERROR! Invalid Route!!!\n");

                orFrame = onion;

                while(node != NULL) {
                    OrUint8 *onionLayer = orFrame;

                    or_mem_copy(orFrame, OR_CHALLENGE_TEXT, OR_CHALLENGE_LEN);
                    orFrame += OR_CHALLENGE_LEN;
                    OR_COPY_UINT8_TO_LITTLE_ENDIAN(node->layerInfo.backF, orFrame);
                    orFrame += OR_BACK_F_LEN;
                    OR_COPY_UINT8_TO_LITTLE_ENDIAN(node->layerInfo.forwF, orFrame);
                    orFrame += OR_BACK_F_LEN;
                    OR_COPY_UINT16_TO_LITTLE_ENDIAN(node->layerInfo.nextmemberId, 
                                                                                orFrame);
                    orFrame += OR_MEMBER_ID_LEN;
                    or_mem_copy(orFrame, node->layerInfo.orBackFkey, 
                                                        OR_FORW_BACK_KEY_LENGTH);
                    orFrame += OR_FORW_BACK_KEY_LENGTH;
                    or_mem_copy(orFrame, node->layerInfo.orForwFkey, 
                                                        OR_FORW_BACK_KEY_LENGTH);
                    orFrame += OR_FORW_BACK_KEY_LENGTH;
                    OR_COPY_UINT32_TO_LITTLE_ENDIAN(node->layerInfo.expTime, orFrame);
                    orFrame += OR_EXP_TIME_LEN;

                    /* encrypt onion layer */
                    or_encrypt_onion_layer(onionLayer, node->orDhSecret);

                    node = node->next;
                }

                orSesnInfo->onion.orOnion = (OrUint8 *)or_mem_alloc
                                                 (route.routeLen * OR_ONION_LAYER_LEN);
                /* copy onion */
                or_mem_copy(orSesnInfo->onion.orOnion, onion, 
                                        (route.routeLen * OR_ONION_LAYER_LEN));
                orSesnInfo->onion.orLen = (route.routeLen * OR_ONION_LAYER_LEN);
            }while(0);

            /* copy route info */
            or_mem_copy(&orSesnInfo->route, &route, sizeof(OrRoute));
            result = TRUE;
        }
        else {
            OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> route not found "
                                      "route-head = %p route-len = %u",
                                            __FUNCTION__, __LINE__,
                                            route.routeHead, route.routeLen);
        }
    }//end if
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> orSesnIfo is NULL",
                                                    __FUNCTION__, __LINE__);
    }

    if(result) {
        OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %d)> The onion is",
                                                    __FUNCTION__, __LINE__);

        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
        for(k = 0; k < orSesnInfo->onion.orLen; k++) {
            OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ", orSesnInfo->onion.orOnion[k]);
        }
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

static void or_onion_proxy_encrypt_pkt(const OrOnionProxySessionEntry *orPxySesn,
                                       OrUint8 *data,
                                       OrUint16 dataLen)
{
    OrUint8 routeLen = 0, k = 1, j = 0;
    OrNodeInfo *node = NULL;
    OrUint8     *key = NULL;
    OrUint8 n = 0, m = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((orPxySesn == NULL), 
        "or_onion_proxy_encrypt_pkt> orPxySesn = NULL!!!\n");

    node = orPxySesn->route.routeHead;
    OR_ASSERT((node == NULL), 
        "or_onion_proxy_encrypt_pkt> orPxySesn->route.routeHead = NULL!!!\n");

    routeLen = orPxySesn->route.routeLen;

    OR_ASSERT((routeLen <= 1), "or_onion_proxy_encrypt_pkt> routeLen <= 1!!!\n");

    n = dataLen / OR_FORW_BACK_KEY_LENGTH;
    m = dataLen % OR_FORW_BACK_KEY_LENGTH;

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "pkt to encrypt\n");
    for(j = 0; j < dataLen; j++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG ,"[%d]: %x ", j+1, data[j]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG,"\n");

    while(routeLen > 0) {
        for(k = 1; k < routeLen; k++) {
            node = node->next;
            OR_ASSERT((node == NULL), 
                    "or_onion_proxy_encrypt_pkt> (node == NULL)!!!\n");
        }

        key = node->layerInfo.orForwFkey;

        OR_XOR_FORW_BACK_KEY_N_TIMES(data, key, n);
        OR_XOR_FORW_BACK_KEY_N_BYTES(data + n * OR_FORW_BACK_KEY_LENGTH, key, m);

        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "pkt after "
                                          "(layer %u) encryption\n",
                                          orPxySesn->route.routeLen - routeLen 
                                          + 1);
        for(j = 0; j < dataLen; j++) {
            OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG ,"[%d]: %x ", j+1, data[j]);
        }
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG,"\n");

        node = orPxySesn->route.routeHead;
        routeLen--;
    }
}

static void or_onion_proxy_decrypt_pkt(const OrOnionProxySessionEntry *orPxySesn,
                                       OrUint8 *data,
                                       OrUint16 dataLen)
{
    OrUint8 routeLen = 0;
    OrNodeInfo *node = NULL;
    OrUint8     *key = NULL;
    OrUint8 n = 0, m = 0, j = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((orPxySesn == NULL), 
        "or_onion_proxy_encrypt_pkt> orPxySesn = NULL!!!\n");

    node = orPxySesn->route.routeHead;
    OR_ASSERT((node == NULL), 
        "or_onion_proxy_encrypt_pkt> orPxySesn->route.routeHead = NULL!!!\n");

    routeLen = orPxySesn->route.routeLen;

    OR_ASSERT((routeLen <= 1), 
        "or_onion_proxy_encrypt_pkt> routeLen <= 1!!!\n");

    n = dataLen / OR_FORW_BACK_KEY_LENGTH;
    m = dataLen % OR_FORW_BACK_KEY_LENGTH;

    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "pkt before decryption\n");
    for(j = 0; j < dataLen; j++) {
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG ,"[%d]: %x ", j+1, data[j]);
    }
    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG,"\n");

    while(node != NULL) {
        key = node->layerInfo.orBackFkey;

        OR_XOR_FORW_BACK_KEY_N_TIMES(data, key, n);
        OR_XOR_FORW_BACK_KEY_N_BYTES(data + n * OR_FORW_BACK_KEY_LENGTH, key, m);

        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "pkt after "
                                  "(layer %u) decryption\n",
                                  orPxySesn->route.routeLen - k++);

        for(j = 0; j < dataLen; j++) {
            OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG ,"[%d]: %x ", j+1, data[j]);
        }
        OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG,"\n");

        node = node->next;
    }
}


static void *or_onion_proxy_rcv_thread(void *thread_param)
{
    OrUint8 buffer[OR_PKT_LEN];
    OrInt nBytesRead = 0;
    OrOnionProxySessionEntry *orPxySesn = (OrOnionProxySessionEntry *)thread_param;
    OrInt   clientFd = -1;
    OrInt   err;
    fd_set rset, eset;
    OrIncmingDataTuple iTuple;
    OrInt result;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    OR_ASSERT((orPxySesn == NULL), 
                    "or_onion_proxy_rcv_thread>Invalid Proxy sesn\n");

    clientFd = orPxySesn->clientFd;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Fd: %i", 
                                    __FUNCTION__, __LINE__, clientFd);

    /* ready read & exception fd set for select */
    FD_ZERO(&rset);
    FD_ZERO(&eset);
    FD_SET(clientFd, &rset);
    FD_SET(clientFd, &eset);

    while(TRUE) {
        or_mem_set(&iTuple, 0x00, sizeof(OrIncmingDataTuple));
        result = select(clientFd + 1, &rset, NULL, &eset, NULL);

        if(result > 0) {
            if(FD_ISSET(clientFd, &rset)) {
                /* wait for incoming data */
                or_mutex_lock(orPxySesn->orOnionPxySndRcvLock);
                nBytesRead = recv(clientFd, buffer, sizeof(buffer), 0);
                or_mutex_unlock(orPxySesn->orOnionPxySndRcvLock);

                err = errno;

                if (nBytesRead < 0)
                {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>"
                                               "errno: %s", 
                                    __FUNCTION__, __LINE__, strerror(errno));
                    OR_ASSERT(!((err == EAGAIN) || (err == EWOULDBLOCK)),
                                        "recv returned unrecoverable error\n");
                }
                else if(nBytesRead != 0) {
                    /* parse incoming data */
                    if(or_parse_incoming_data(buffer, nBytesRead, &iTuple)) {
                        OR_ASSERT((or_mem_cmp(orPxySesn->route.linkKey,
                                    iTuple.linkKey, OR_DH_SECRET_LENGTH)), 
                                    "or_onion_proxy_rcv_thread>link key does "
                                    "not match after challenge cryption\n");
                    
                        if(iTuple.cid == orPxySesn->vcId) {
                            switch(iTuple.cmd) {
                                case OR_DATA_CMD:
                                {
                                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> ORProxy "
                                                                 "received data cmd.for "
                                                                 "(member %u)",
                                                     __FUNCTION__, __LINE__, orPxySesn->memberId);
                                    /* crypt pload using backF */
                                    or_onion_proxy_decrypt_pkt(orPxySesn, iTuple.pLoad, 
                                                                                iTuple.pLoadL);
                                    /* pass message to respective app proxy */
                                    orPxySesn->appDataIndFn(orPxySesn->orSesnProxyTriplet.sessionId,
                                                                 iTuple.pLoad, iTuple.pLoadL);
                                }
                                break;
                                case OR_CREATE_CMD:
                                case OR_DESTROY_CMD:
                                case OR_PADDING_CMD:
                                default:
                                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Unhandled "
                                                                 "cmd %u. Ignoring data",
                                                                __FUNCTION__, __LINE__, iTuple.cmd);
                                break;
                            }
                        }
                        else {
                            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> vcid does not "
                                                   "match in incoming data. Ignoring data"
                                                            ,__FUNCTION__, __LINE__);
                        }
                    }//if(!or_parse_incoming_data(buffer, nBytesRead, &iTuple))
                    else {
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                "Ignoring incoming. Could not parse"
                                ,__FUNCTION__, __LINE__);
                    }
                }//if(nBytesRead != 0)
            }//end if(FD_ISSET(clientFd, &rset))

            if(FD_ISSET(clientFd, &eset)) {
                OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>"
                           "errno: %s", 
                __FUNCTION__, __LINE__, strerror(errno));
                OR_ASSERT(TRUE, "or_onion_proxy_rcv_thread> read exception\n");
            }// if(FD_ISSET(clientFd, &eset))
        }//if(result > 0)
        or_mem_free(iTuple.pLoad);
    }//end while 

    EXIT_THREAD(NULL);
}

static void *or_onion_proxy_snd_thread(void *thread_param)
{
    OrInt   clientFd   = -1;
    OrSesnData *pnode = NULL;
    OrOnionProxySessionEntry *orPxySesn = (OrOnionProxySessionEntry *)thread_param;
    OrUint8 nNodesInQ = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    OR_ASSERT((orPxySesn == NULL), "Invalid Proxy sesn\n");

    clientFd = orPxySesn->clientFd;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Fd: %i", 
                                    __FUNCTION__, __LINE__, clientFd);

#if 0
    /* Initially down the sema so that the thread can wait on it
     * looking for a signal from data sender */
    OR_ASSERT(!or_sema_wait(&orPxySesn->orOnionPxySndSema),
              "or_onion_proxy_snd_thread>Sema wait failed!!!\n");
#endif

    while(TRUE) {
        /* sema wait */
        OR_ASSERT(!or_sema_wait(&orPxySesn->orOnionPxySndSema),
                          "or_onion_proxy_snd_thread>Sema wait failed!!!\n");
        pnode = orPxySesn->orSesnDataH;
        nNodesInQ = 0;
        /* find if this session has any outgoing data pending */
        if(pnode != NULL) {
            nNodesInQ++;
            while(pnode->next != NULL) {
                nNodesInQ++;
                pnode = pnode->next;
            }
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                        "No of nodes in data Q: %u", 
                                        __FUNCTION__, __LINE__, nNodesInQ);
            if(pnode->orPktL > 0) {
                OrInt nbytes = 0;
                or_mutex_lock(orPxySesn->orOnionPxySndRcvLock);
                /* send data */
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                           "Sending data in fd: %i", 
                                            __FUNCTION__, __LINE__, clientFd);
                nbytes = write(clientFd, pnode->orPkt, pnode->orPktL);
                printf("Sent %u bytes\n", pnode->orPktL);
                or_mutex_unlock(orPxySesn->orOnionPxySndRcvLock);

                if(nbytes > 0) {
                    OR_ASSERT((nbytes > OR_PKT_LEN),
                        "or_onion_proxy_snd_thread> Invalid write\n");
                    if(nbytes < pnode->orPktL) {
                        pnode->orPktL -= nbytes;
                        or_mem_copy(pnode->orPkt, 
                                    &pnode->orPkt[nbytes], pnode->orPktL);
                    }
                    else {
                        or_mutex_lock(orPxySesn->orOnionPxySndQLock);
                        or_util_remove_node_from_list(orPxySesn->orSesnDataH,
                                                            OrSesnData, pnode);
#if 0
                        /* TBD: If we data Q has more than 1 data pending
                         * to be sent then since this thread acquires the
                         * lock immediately it sends the next data immediately.
                         * Rcvr receives two pkts at the same read. Since the
                         * rcvr doesn't yet have the capability to handle two
                         * pkts at the same read the following hack is employed.
                         * Note that rcvr can handle multiple incoming pkts
                         * through multiple reads */
                        if(nNodesInQ > 1) {sleep(2);}
#endif
                        or_mutex_unlock(orPxySesn->orOnionPxySndQLock);
                    }
                }
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                           "Deleting node with 0 len data", 
                                            __FUNCTION__, __LINE__);
                or_mutex_lock(orPxySesn->orOnionPxySndQLock);
                or_util_remove_node_from_list(orPxySesn->orSesnDataH,
                                                    OrSesnData, pnode);
                or_mutex_unlock(orPxySesn->orOnionPxySndQLock);
            }
        }//end if(pnode != NULL)
        else
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                       "orSesnDataH is NULL\n",
                                        __FUNCTION__, __LINE__);
        }
    }//end while

    EXIT_THREAD(NULL);
}

/*-------------------------Public Fn Defn---------------------------------*/

void or_onion_proxy_init()
{
    OrUint8 itr = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);


    or_util_destroy_list(orOnionProxySesnTable, OrOnionProxySessionEntry);
    or_util_destroy_list(orKnownSrcPool, OrSrcPool);
    or_util_destroy_list(orMmemberNeighborTablePairPool, OrMemberNeighborTablePairPool);

    OR_INIT_Q(orAvlblSesnId);
    OR_INIT_Q(orAvlblVcId);

    /* Add ids to the Q */
    for(itr = 1; itr <= OR_ONION_PROXY_MAX_SESSION; itr++) {
        OR_Q_PUT(orAvlblSesnId, itr);
    }
    for(itr = 1; itr <= OR_ONION_PROXY_MAX_SESSION; itr++) {
        OR_Q_PUT(orAvlblVcId, itr);
    }
}

OrBool or_onion_proxy_data_req(OrUint32 memberId,
                               OrUint8 sessionId,
                               OrUint8 *data,
                               OrUint16 dataLength)
{
    OrBool result  = FALSE;
    OrUint8 *orPkt = NULL;
    OrOnionProxySessionEntry *orPxySesn = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    /* check whether the sessionId exists or not. 
     * return failure if it does not exist */

    if(or_onion_proxy_is_active_session(memberId, sessionId, &orPxySesn)) {
        if(orPxySesn != NULL) {
            OrUint8 mac[OR_MAC_FLD_LEN] = {0xff};
            OrSesnData *pSesnData       = NULL;

            /* encrypt pkt with for back key of all intermediate + dest nodes */
            or_onion_proxy_encrypt_pkt(orPxySesn, data, dataLength);
            /* create pkt */
            or_create_or_pkt(orPxySesn->route.linkKey,orPxySesn->vcId, OR_DATA_CMD, 
                    orPxySesn->payLoadType, data,  dataLength, mac, &orPkt);

            OR_ASSERT((orPkt == NULL), 
                "or_onion_proxy_data_req> or pkt create failed\n");

            pSesnData = (OrSesnData *)or_mem_alloc(sizeof(OrSesnData));
            OR_ASSERT((pSesnData == NULL), 
                    "or_onion_proxy_data_req> mem alloc failed\n");
            or_mem_set(pSesnData, 0x00, sizeof(OrSesnData));

            /* copy pkt to sesn data */
            or_mem_copy(pSesnData->orPkt, orPkt, OR_PKT_LEN);
            pSesnData->orPktL = OR_PKT_LEN;

            or_mutex_lock(orPxySesn->orOnionPxySndQLock);
            /* add node to sesn data q */
            or_util_add_to_list_head(orPxySesn->orSesnDataH, OrSesnData, pSesnData);
            or_mutex_unlock(orPxySesn->orOnionPxySndQLock);

            /* free or pkt */
            or_mem_free(orPkt);

            /* signal send thread */
            OR_ASSERT(!or_sema_release(&orPxySesn->orOnionPxySndSema),
                                        "Sema release failed!!!\n");
            result = TRUE;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

OrBool or_onion_proxy_create_or_session_req(OrUint32 memberId,
                                            OrDestAddress dest,
                                            OrProtocol proto,
                                            OrAppProxyDataInd appDataIndFn,
                                            OrUint8 *sessionId)
{
    /* Use the proto field to see if the req field is for 
       delay-tolerant data or not and whether the protocol
       is allowed or not */
    OrOnionProxySessionEntry *node = NULL;
    OrUint8 sesnId                 = OR_INVALID_SESSION_ID;
    OrBool result                  = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> (member id: %u)",
                                    __FUNCTION__, __LINE__, memberId);

    if(or_onion_proxy_does_member_neighbor_table_pair_exist(memberId)) {
        node = (OrOnionProxySessionEntry *) or_mem_alloc(sizeof(OrOnionProxySessionEntry));

        if(node != NULL) {
            node->memberId                 = memberId;
            node->orSesnProxyTriplet.dest  = dest;
            node->orSesnProxyTriplet.proto = proto;
            node->appDataIndFn             = appDataIndFn;
            node->clientFd                 = -1;
            node->orOnionProxyRcvThread    = 0;
            node->orOnionProxySndThread    = 0;
            node->orOnionPxySndRcvLock     = NULL;
            node->orSesnDataH                = NULL;
            node->onion.orOnion            = NULL;
            node->onion.orLen              = 0;
            or_mem_set(node->onion.mac, 0xff, OR_MAC_SIZE);
            or_mem_set(&node->route, 0x00, sizeof(OrRoute));
            node->next = NULL;
            /* Not sure how to init this ? */
            /* node->orOnionPxySndSema        = (OrSemaHandle)0; */

            if(proto == OR_PROTO_SMTP) {
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Requested session is "
                                        "delay tolerant", __FUNCTION__, __LINE__);
                node->payLoadType = OR_PAYLOAD_DELAY_TOLERANT_T;
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Requested session is "
                                        "delay intolerant", __FUNCTION__, __LINE__);
                node->payLoadType = OR_PAYLOAD_DELAY_INTOLERANT_T;
            }

            /* does session exist already */
            if(!or_onion_proxy_does_session_exist(node)) {
                /* Create an onion */

                if(or_onion_proxy_create_onion(memberId, dest, node)) {
                    if(!OR_IS_Q_EMPTY(orAvlblSesnId)) {
                        /* assign sessionId */
                         OR_Q_GET(orAvlblSesnId, node->orSesnProxyTriplet.sessionId);
                        if(!OR_IS_Q_EMPTY(orAvlblVcId)) {
                            OrUint8 *pkt = NULL;
                            OrUint8 mac[OR_MAC_FLD_LEN] = {0xff};
                            OrInt8 isConnect = 0;

                            /* assign VC id */
                            OR_Q_GET(orAvlblVcId, node->vcId);

                            /* create a pkt */
                            if(or_create_or_pkt(node->route.linkKey,
                                node->vcId, OR_CREATE_CMD,
                                node->payLoadType, node->onion.orOnion,
                                node->onion.orLen, mac, &pkt)) {

                                /* Setup connection with next hop */
                                if((isConnect = or_connect_to_remote_server(&node->clientFd, 
                                        node->route.nextHopAddr.ip,
                                        node->route.nextHopAddr.port,
                                        OR_HOST_IP)) >= 0){
                                    OrUint8 buffer[100];
                                    OrInt nBytes = 0;

                                    /* send pkt */
                                    nBytes = write(node->clientFd, pkt, OR_PKT_LEN);
                                    OR_ASSERT((nBytes != OR_PKT_LEN), 
                                        "or_o_pxy_create_or_sesn_req> Onion not sent\n");

                                    nBytes = 0;

                                    nBytes = recv(node->clientFd, buffer, sizeof(buffer), 0);

                                    if(nBytes > 0) {
                                        buffer[nBytes] = '\0';

                                        if(!strcmp(buffer, "success")) {
                                            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                            "VC setup success for OR route!!!", 
                                            __FUNCTION__, __LINE__);
                                            /* Create Mutexes */
                                            OR_ASSERT(!or_mutex_create(&node->orOnionPxySndRcvLock),
                                                                  "Mutex create failed\n");
                                            OR_ASSERT(!or_mutex_create(&node->orOnionPxySndQLock),
                                                                  "Mutex create failed\n");
                                            /* create semaphore */
                                            OR_ASSERT(!or_sema_create(&node->orOnionPxySndSema),
                                                                  "Sema create failed\n");
                                            /* create receive thread */
                                            if(!(CREATE_THREAD(&node->orOnionProxyRcvThread, 
                                                NULL, or_onion_proxy_rcv_thread, 
                                                node) < 0)) {
                                                /* create send thread */
                                                if(!(CREATE_THREAD(&node->orOnionProxySndThread, 
                                                NULL, or_onion_proxy_snd_thread, 
                                                node) < 0)) {
                                                    /* add new session to table */
                                                    or_util_add_to_list(orOnionProxySesnTable,
                                                    OrOnionProxySessionEntry, node);
                                                    *sessionId = node->orSesnProxyTriplet.sessionId;
                                                    result = TRUE;
                                                }
                                                else {
                                                    /* destroy rcv thread */
                                                    DESTORY_THREAD(node->orOnionProxyRcvThread);
                                                    or_mutex_destroy(node->orOnionPxySndRcvLock);
                                                    or_sema_destroy(node->orOnionPxySndSema);
                                                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                                    "send thread create failed!!!", 
                                                    __FUNCTION__, __LINE__);
                                                }
                                            }
                                            else {
                                                or_mutex_destroy(node->orOnionPxySndRcvLock);
                                                or_sema_destroy(node->orOnionPxySndSema);
                                                OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                                "rcv thread create failed!!!", 
                                                __FUNCTION__, __LINE__);
                                            }
                                        }
                                        else {
                                            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                            "VC create failed!!!", 
                                            __FUNCTION__, __LINE__);
                                        }
                                    }
                                    else {
                                        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                        "Invalid read!!!", 
                                        __FUNCTION__, __LINE__);
                                    }
                                }
                                else {
                                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                    "Connection to next hop failed!!!", 
                                    __FUNCTION__, __LINE__);
                                }
                                /* free pkt */
                                or_mem_free(pkt);
                                pkt = NULL;
                            }
                            else {
                                OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                                    "pkt creation failed", 
                                                    __FUNCTION__, __LINE__);
                            }
                        }
                        else {
                            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> No avialable " 
                                                       "VC ids", __FUNCTION__, __LINE__);
                        }
                    }
                    else {
                        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> No avialable session", 
                                                                    __FUNCTION__, __LINE__);
                    }
                }
                else {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                            "Failed to create onion."
                                            ,__FUNCTION__, __LINE__);
                }
            }
            else {
                *sessionId = node->orSesnProxyTriplet.sessionId;
                /* session already exist. free node */
                or_mem_free(node);
                node = NULL;
                result = TRUE;
            }
        }
        else {
            OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> memory allocation failed", 
                                                    __FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> member neighbor table pair "
                                   "does not exist for member: %u", 
                                        __FUNCTION__, __LINE__, memberId);
    }

OUT:
    if(result == FALSE && node != NULL) {
        if(node->clientFd != -1) {
            close(node->clientFd);
        }
        or_mem_free(node);
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

OrBool or_onion_proxy_destroy_or_session_req(OrUint32 memberId, OrUint8 sessionId)
{
    /* Use the proto field to see if the req field is for 
       delay-tolerant data or not and whether the protocol
       is allowed or not */
       OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);
}

void or_onion_proxy_update_neighbor_table_for_member(OrUint32 memberId,
                                                     OrNeighborTable *neighborTable)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(neighborTable != NULL) {
        OrMemberNeighborTablePairPool *node = NULL;

        node = (OrMemberNeighborTablePairPool *)or_mem_alloc(sizeof(OrMemberNeighborTablePairPool));
        if(node != NULL) {
            node->memberNbrTablePair.memberId      = memberId;
            node->memberNbrTablePair.neighborTable = neighborTable;
            node->next                             = NULL;

            or_util_add_to_list(orMmemberNeighborTablePairPool, 
                                OrMemberNeighborTablePairPool, node);

            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> neighbor table updated "
                    "for member:%d", __FUNCTION__, __LINE__, memberId);
        }
        else {
            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> memory allocation failed", 
                                                    __FUNCTION__, __LINE__);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> empty neighbor table", __FUNCTION__, __LINE__);
    }
}

void or_onion_proxy_deinit()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(orOnionProxySesnTable != NULL) {
        /* TBD: destroy route */
        /* TBD: close FDs */
        /* TBD: destroy snd/rcv threads */
        /* TBD: destroy mutex */

        /* TBD: destroy onion */

        or_util_destroy_list(orOnionProxySesnTable, OrOnionProxySessionEntry);
    }

    or_util_destroy_list(orKnownSrcPool, OrSrcPool);
    or_util_destroy_list(orMmemberNeighborTablePairPool, OrMemberNeighborTablePairPool);

    OR_Q_DESTROY(orAvlblSesnId);
    OR_Q_DESTROY(orAvlblVcId);
}

#ifdef OR_TEST_MODE
void or_replay_onion(void) {
    OrOnionProxySessionEntry * node =orOnionProxySesnTable;
    OrSesnData *pSesnData       = NULL;
    OrUint8 mac[OR_MAC_SIZE]    = {0xff};
    OrUint8 *pkt                = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(node == NULL) {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                   "Can't replay onion. "
                                   "No active onion proxy "
                                   "sesn found. Try again after "
                                   "registering an app sesn with onion proxy."
                                   , __FUNCTION__, __LINE__);
    }
    else {
        /* create a pkt */
        if(or_create_or_pkt(node->route.linkKey,
            node->vcId, OR_CREATE_CMD,
            node->payLoadType, node->onion.orOnion,
            node->onion.orLen, mac, &pkt)) {

            OR_ASSERT((pkt == NULL), 
                "or_replay_onion> unrecoverable error in pkt formation\n");

            pSesnData = (OrSesnData *)or_mem_alloc(sizeof(OrSesnData));
            OR_ASSERT((pSesnData == NULL), 
                    "or_replay_onion> mem alloc failed\n");
            or_mem_set(pSesnData, 0x00, sizeof(OrSesnData));

            /* copy pkt to sesn data */
            or_mem_copy(pSesnData->orPkt, pkt, OR_PKT_LEN);
            pSesnData->orPktL = OR_PKT_LEN;

            or_mutex_lock(node->orOnionPxySndQLock);
            /* add node to sesn data q */
            or_util_add_to_list_head(node->orSesnDataH, OrSesnData, pSesnData);
            or_mutex_unlock(node->orOnionPxySndQLock);

            /* free or pkt */
            or_mem_free(pkt);

            /* signal send thread */
            OR_ASSERT(!or_sema_release(&node->orOnionPxySndSema),
                                        "Sema release failed!!!\n");
        }
        else {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                       "Onion not replayed. "
                                       "Or pkt formation error!!!",
                                       __FUNCTION__, __LINE__);
        }
    }
}

OrBool or_onion_proxy_dummy_msg_req(OrUint32 memberId,
                                    OrUint8 sessionId)
{
    OrBool result  = FALSE;
    OrUint8 *orPkt = NULL;
    OrUint8 data[OR_PAYLD_FLD_LEN] = {0xff};
    OrOnionProxySessionEntry *orPxySesn = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    /* check whether the sessionId exists or not. 
     * return failure if it does not exist */

    if(or_onion_proxy_is_active_session(memberId, sessionId, &orPxySesn)) {
        if(orPxySesn != NULL) {
            OrUint8 mac[OR_MAC_FLD_LEN] = {0xff};
            OrSesnData *pSesnData       = NULL;

            /* create pkt */
            or_create_or_pkt(orPxySesn->route.linkKey,orPxySesn->vcId, 
                             OR_PADDING_CMD, orPxySesn->payLoadType, 
                             data,  OR_PAYLD_FLD_LEN, mac, &orPkt);

            OR_ASSERT((orPkt == NULL), 
                "or_onion_proxy_dummy_msg_req> or pkt create failed\n");

            pSesnData = (OrSesnData *)or_mem_alloc(sizeof(OrSesnData));
            OR_ASSERT((pSesnData == NULL), 
                    "or_onion_proxy_dummy_msg_req> mem alloc failed\n");
            or_mem_set(pSesnData, 0x00, sizeof(OrSesnData));

            /* copy pkt to sesn data */
            or_mem_copy(pSesnData->orPkt, orPkt, OR_PKT_LEN);
            pSesnData->orPktL = OR_PKT_LEN;

            or_mutex_lock(orPxySesn->orOnionPxySndQLock);
            /* add node to sesn data q */
            or_util_add_to_list_head(orPxySesn->orSesnDataH, OrSesnData, pSesnData);
            or_mutex_unlock(orPxySesn->orOnionPxySndQLock);

            /* free or pkt */
            or_mem_free(orPkt);

            /* signal send thread */
            OR_ASSERT(!or_sema_release(&orPxySesn->orOnionPxySndSema),
                                        "Sema release failed!!!\n");
            result = TRUE;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

#endif
