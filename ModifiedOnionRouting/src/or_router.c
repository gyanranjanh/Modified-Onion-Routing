/*
 * FILE:	or_router.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_router.h"
#include "or_common.h"
#include "or_util.h"
#include "or_time.h"
#include "or_log.h"
#include "or_security_module.h"

/*------------------------Local Macros--------------------------*/
#define OR_ROUTER_MAX_AVLBL_VCS    (10)

#define or_router_count_no_of_msgs_in_mix(n)  \
do{                                           \
    OrDlyTolerantData *nodez = orMixPool;     \
    n = 0;                                    \
    while(nodez != NULL) {                    \
        n++;                                  \
        nodez = nodez->mixnext;               \
    }                                         \
}while(0)
/*------------------------Local Variables & Data----------------*/
static OrOnionList           *orExpdOnionList = NULL;
static OrOnionList         *orUnExpdOnionList = NULL;
static OrCktDataPool           *orCktDataPool = NULL;
static OrMutexHandle      orExpdOnionListLock = NULL;
static OrMutexHandle    orUnExpdOnionListLock = NULL;
static OrMutexHandle            orFwdPathLock = NULL;
static OrMutexHandle            orMixPoolLock = NULL;
static OrDlyTolerantData           *orMixPool = NULL;

OR_CREATE_Q(OrUint8, orAvlblVcId);
/*-------------------------Local Fn Decl------------------------*/
static void or_router_parse_onion_layer(const OrUint8 *decptdOnionLayer, 
                                          OrCktSpecificData *cktDataNode);
static void or_router_crypt_data(OrCktSpecificData *cktData,
                                 OrIncmingDataTuple *iTuple,
                                 OrCryptoDir cryptoDir);
static void or_router_fire_mix_if_possible(void);
static void * or_router_rcv_thread(void *thread_param);
static void * or_router_snd_thread(void *thread_param);
static void * or_router_timer_thread(void *thread_param);
/*-------------------------Local Fn Defn------------------------*/
static void or_router_parse_onion_layer(const OrUint8 *decptdOnionLayer, 
                                        OrCktSpecificData *cktDataNode)
{
    const OrUint8 *pdata = decptdOnionLayer;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((decptdOnionLayer == NULL), 
        "or_router_parse_onion_layer> decptdOnionLayr is NULL\n");
    OR_ASSERT((cktDataNode == NULL), 
        "or_router_parse_onion_layer> cktDataNode is NULL\n");

    /*
    Each layer of onion
    ++++++++++++++++++++++++++++++++++++++++++++
    + Back F(1) + Forw F(1) + Next MemberId(2) +
    ++++++++++++++++++++++++++++++++++++++++++++
    +            Back F Key(16)                +
    +            Forw F Key(16)                +
    ++++++++++++++++++++++++++++++++++++++++++++
    +             Exp Time(4)                  +
    ++++++++++++++++++++++++++++++++++++++++++++
    total length 40 bytes
    */

    cktDataNode->layerInfo.backF = pdata[0];
    pdata += OR_BACK_F_LEN;
    cktDataNode->layerInfo.forwF = pdata[0];
    pdata += OR_FORW_F_LEN;
    cktDataNode->layerInfo.nextmemberId = 
                    OR_GET_UINT16_FROM_LITTLE_ENDIAN(pdata);
    pdata += OR_MEMBER_ID_LEN;
    or_mem_copy((void *)cktDataNode->layerInfo.orBackFkey,
                            (void *)pdata, OR_FORW_BACK_KEY_LENGTH);
    pdata += OR_FORW_BACK_KEY_LENGTH;
    or_mem_copy((void *)cktDataNode->layerInfo.orForwFkey,
                            (void *)pdata, OR_FORW_BACK_KEY_LENGTH);
    pdata += OR_FORW_BACK_KEY_LENGTH;
    cktDataNode->layerInfo.expTime = OR_GET_UINT32_FROM_LITTLE_ENDIAN(pdata);
}

static void or_router_fire_mix_if_possible(void)
{
    OrUint8  nmsgsInMix, rnd = 0, prnd = 0, k = 0, j = 0;
    OrDlyTolerantData *traverse = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    /* check can the mix fire. MIX fires s msgs
     * chosen at random, if n+s mesgs accumulates */
    /* later we will improve s as s = nP(n).*/
    or_router_count_no_of_msgs_in_mix(nmsgsInMix);

    prnd = rnd;

    if(nmsgsInMix >= OR_MIX_PARAM_N + OR_MIX_PARAM_S) {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                           "Mix can fire. No "
                           "msgs is %u", 
                        __FUNCTION__, __LINE__, nmsgsInMix);
        while(j < OR_MIX_PARAM_S) {
            srand((unsigned)clock());
            rnd = or_get_random_at_most(nmsgsInMix) & 0xFF;

            k = 0;
            traverse = orMixPool;
            while(traverse != NULL) {
                k++;
                if(k == rnd) {
                    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                               "marked %u for firing. %p", 
                                            __FUNCTION__, __LINE__,
                                            k, traverse);

                    traverse->fire = TRUE;
                    break;
                }
                traverse = traverse->mixnext;
            }
            if(k != rnd) { continue;}
            if(prnd == rnd) {
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                           "prnd == rnd",
                                         __FUNCTION__, __LINE__);
                continue;
            }
            prnd = rnd;
            j++;
        }
    }
    else {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                       "Mix can't fire. No "
                                       "msgs is %u", 
                                    __FUNCTION__, __LINE__, nmsgsInMix);
    }

    /* Now go through the mix pool fire the ones which are just marked */
    traverse = orMixPool;
    while(traverse != NULL) {
        if(traverse->fire == TRUE) {
            OrCktSpecificData *cktData = traverse->rfnceToCktData;
            if(cktData != NULL) {
                /* pass message to forward link */
                /* signal send thread */
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                           "firing %p "
                                           "for non-init data. "
                                           "ckt data is:: %p", 
                                        __FUNCTION__, __LINE__,
                                        traverse, cktData);
                or_mutex_lock(cktData->orDlyTolerantQLock);
                or_mutex_lock(orMixPoolLock);
                or_util_remove_from_mixpool(orMixPool, OrDlyTolerantData, traverse);
                or_mutex_unlock(orMixPoolLock);
                or_mutex_unlock(cktData->orDlyTolerantQLock);
#if 0
                or_router_count_no_of_msgs_in_mix(nmsgsInMix);
                printf("No of msgs in mix: %u\n", nmsgsInMix);
#endif
                OR_ASSERT(!or_sema_release(&cktData->orRouterSndSema),
                                            "Sema release failed!!!\n");
            }
            else {
                OrCktSpecificData *pnode = NULL;
                /* to trigger dummy msg */

                /* find a delay tolerant ckt */
                or_util_find_node_in_list(orCktDataPool, OrCktSpecificData,
                             pldType, OR_PAYLOAD_DELAY_TOLERANT_T, pnode);
                /* printf("found delay tolerant cktdata for init pad: %p\n", 
                pnode);*/

                if(pnode == NULL) {
                    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                       "Can't find delay tolerant ckt. "
                                       "Dummy msg not sent. ", 
                                        __FUNCTION__, __LINE__);
                }
                else {
                    OrUint8 *orPkt                  = NULL;
                    OrUint8 dummy[OR_PAYLD_FLD_LEN] = {0xff};
                    OrUint8 mac[OR_MAC_SIZE]        = {0xff};

                    traverse->rfnceToCktData = pnode;

                    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                               "firing %p.", 
                                            __FUNCTION__, __LINE__, traverse);

                    /* form an or pkt */
                    if(or_create_or_pkt(pnode->nextHopLinkKey,
                        pnode->nextHopVcId, OR_PADDING_CMD,
                        pnode->pldType, dummy, OR_PAYLD_FLD_LEN - 1, /* TBD */
                        mac, &orPkt)) {
                        OR_ASSERT((orPkt == NULL),
                            "or_router_fire_mix_if_possible> Fatal Error: "
                            "orPkt is NULL");

                        traverse->data  = orPkt;
                        traverse->dataL = OR_PKT_LEN;

                        or_mutex_lock(pnode->orDlyTolerantQLock);
                        or_mutex_lock(orMixPoolLock);
                        or_util_add_to_list(pnode->orDlyTolrntDataQh, 
                                                OrDlyTolerantData, traverse);
                        or_util_remove_from_mixpool(orMixPool,
                                                   OrDlyTolerantData, traverse);
#if 0
                        or_router_count_no_of_msgs_in_mix(nmsgsInMix);
                        printf("No of msgs in mix: %u\n", nmsgsInMix);
#endif
                        or_mutex_unlock(orMixPoolLock);
                        or_mutex_unlock(pnode->orDlyTolerantQLock);

                        OR_ASSERT(!or_sema_release(&pnode->orRouterSndSema),
                                                    "Sema release failed!!!\n");
                    }
                }//end if(pnode == NULL)
            }// end if(cktData != NULL)
            traverse = orMixPool;
        } //end (traverse->fire == TRUE)
        else {
            traverse = traverse->mixnext;
        }
    }//end while(traverse != NULL)

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> <<", 
                                __FUNCTION__, __LINE__);
}

static void or_router_crypt_data(OrCktSpecificData *cktData,
                                 OrIncmingDataTuple *iTuple,
                                 OrCryptoDir cryptoDir)
{
    OrUint8     *key = NULL;
    OrUint8 n = 0, m = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    OR_ASSERT((cktData == NULL), "Invalid ckt data\n");
    OR_ASSERT((iTuple == NULL), "Invalid incoming tuple\n");


    n = iTuple->pLoadL / OR_FORW_BACK_KEY_LENGTH;
    m = iTuple->pLoadL % OR_FORW_BACK_KEY_LENGTH;

    if(cryptoDir == OR_CRYPTO_DIR_BCK){
        key = cktData->layerInfo.orBackFkey;
    }
    else {
        key = cktData->layerInfo.orForwFkey;
    }

    OR_XOR_FORW_BACK_KEY_N_TIMES(iTuple->pLoad, key, n);
    OR_XOR_FORW_BACK_KEY_N_BYTES(iTuple->pLoad + n * OR_FORW_BACK_KEY_LENGTH, key, m);
}

static void * or_router_rcv_thread(void *thread_param)
{
    OrUint8 buffer[2048];
    OrInt nBytesRead = 0;
    OrCktSpecificData *cktData = (OrCktSpecificData *)thread_param;
    OrInt   clientFd = -1;
    OrInt   err;
    OrIncmingDataTuple iTuple;
    fd_set rset, eset;
    OrInt result;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    OR_ASSERT((cktData == NULL), "Invalid ckt data\n");

    or_mem_set(&iTuple, 0x00, sizeof(OrIncmingDataTuple));

    clientFd = cktData->nextHopFd;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Fd: %i", 
                                    __FUNCTION__, __LINE__, clientFd);

    /* ready read & exception fd set for select */
    FD_ZERO(&rset);
    FD_ZERO(&eset);
    FD_SET(clientFd, &rset);
    FD_SET(clientFd, &eset);

    while(TRUE) {
        result = select(clientFd + 1, &rset, NULL, &eset, NULL);
        if(result > 0) {
            if(FD_ISSET(clientFd, &rset)) {
                /* wait for incoming data */
                or_mutex_lock(cktData->orRouterSndRcvLock);
                nBytesRead = recv(clientFd, buffer, sizeof(buffer), 0);
                or_mutex_unlock(cktData->orRouterSndRcvLock);

                err = errno;

                if (nBytesRead < 0)
                {
                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>"
                               "errno: %s", __FUNCTION__, __LINE__, strerror(errno));
                    OR_ASSERT(!((err == EAGAIN) || (err == EWOULDBLOCK)),
                                        "recv returned unrecoverable error\n");
                }
                else if(nBytesRead != 0) {
                    OrUint8  m = 0, k = 0;
                    OrUint16 n = 0;

                    m = nBytesRead / OR_PKT_LEN;
                    n = nBytesRead % OR_PKT_LEN;

                    /* TBD: We are ignoring n bytes for now. */
                    UNUSED(n);

                    /* parse incoming data */
                    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                               "Data rcvd in fd: %u", 
                                               __FUNCTION__, __LINE__, clientFd);
                    while(m > 0) {
                        if(or_parse_incoming_data(buffer + k * OR_PKT_LEN,
                            OR_PKT_LEN, &iTuple)) {
                            OR_ASSERT((or_mem_cmp(cktData->nextHopLinkKey,
                            iTuple.linkKey, OR_DH_SECRET_LENGTH)),
                            "or_router_rcv_thread> Link key doesn't match after " 
                            "challenge decyption\n");
                            if(iTuple.cid == cktData->nextHopVcId) {
                                switch(iTuple.cmd) {
                                    case OR_DATA_CMD:
                                    {
                                        OrUint8 *pkt = NULL;
                                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> OR router "
                                                                     "received data cmd from "
                                                                     "(member %u)",
                                                         __FUNCTION__, __LINE__, 
                                                         cktData->layerInfo.nextmemberId);
                                        /* crypt pload using backF */
                                        or_router_crypt_data(cktData, &iTuple, OR_CRYPTO_DIR_BCK);
                                        /* form an or pkt */
                                        if(or_create_or_pkt(cktData->linkKey,
                                            cktData->vcId, OR_DATA_CMD,
                                            iTuple.pLoadT, iTuple.pLoad, iTuple.pLoadL,
                                            iTuple.mac, &pkt))
                                        {
                                            /* pass message to respective back link */
                                            or_sock_write_req(cktData->fd, pkt, OR_PKT_LEN);
                                        }
                                        else {
                                            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                                             "OR pkt formation failed!!! ",
                                                                 __FUNCTION__, __LINE__);
                                        }
                                        or_mem_free(pkt);
                                    }
                                    break;
                                    case OR_CREATE_CMD:
                                    case OR_DESTROY_CMD:
                                    case OR_PADDING_CMD:
                                    default:
                                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Unhandled cmd "
                                                                     "%u. Ignoring data",
                                                                    __FUNCTION__, __LINE__, iTuple.cmd);
                                    break;
                                }
                            }
                            else {
                                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> vcid does not match "
                                                            "in incoming data. Ignoring data",
                                                                __FUNCTION__, __LINE__);
                            }
                        }
                        else {
                            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                "Incoming data couldn't be parsed. Ignoring data.",
                                                            __FUNCTION__, __LINE__);
                        }
                        or_mem_free(iTuple.pLoad);
                        or_mem_set(&iTuple, 0x00, sizeof(OrIncmingDataTuple));
                        k++;
                        m--;
                    }//end while(m > 0)
                }//end if(nBytesRead != 0)
            }//end if(FD_ISSET(clientFd, &rset))

            if(FD_ISSET(clientFd, &eset)) {
                OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)>"
                           "errno: %s", 
                __FUNCTION__, __LINE__, strerror(errno));
                OR_ASSERT(TRUE, "or_router_rcv_thread> read exception\n");
            }
        }//end if(result > 0)
        else {
            err = errno;
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> vcid does not match "
                            "in incoming data. Ignoring data",
                                __FUNCTION__, __LINE__);
        }
    }//end while
}

static void * or_router_snd_thread(void *thread_param)
{
    OrInt   clientFd = -1;
    OrCktSpecificData *cktData = (OrCktSpecificData *)thread_param;
    OrOutgoingCktData *pnode   = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                            __FUNCTION__, __LINE__);

    OR_ASSERT((cktData == NULL), "Invalid ckt data\n");

    clientFd = cktData->nextHopFd;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Fd: %i", 
                                    __FUNCTION__, __LINE__, clientFd);

    while(TRUE) {
        /* sema wait */
        OR_ASSERT(!or_sema_wait(&cktData->orRouterSndSema),
                                            "Sema wait failed!!!\n");
        /* delay intolerant data gets more priority */
        pnode = cktData->orOutGngDataQh;
        if(pnode != NULL) {
            while(pnode->next != NULL) {
                pnode = pnode->next;
            }
            if(pnode->data != 0 && pnode->dataL > 0) {
                OrInt nbytes = 0;
                or_mutex_lock(cktData->orRouterSndRcvLock);
                /* send data */
                nbytes = write(clientFd, pnode->data, pnode->dataL);
                or_mutex_unlock(cktData->orRouterSndRcvLock);

                if(nbytes < pnode->dataL) {
                    pnode->dataL -= nbytes;
                    or_mem_copy(pnode->data, &pnode->data[nbytes], pnode->dataL);
                }
                else {
                    or_mutex_lock(cktData->orOutGngQLock);
                    or_mem_free(pnode->data);
                    or_util_remove_node_from_list(cktData->orOutGngDataQh,
                                                    OrOutgoingCktData, pnode);
                    or_mutex_unlock(cktData->orOutGngQLock);
                }
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                           "Deleting node with invalid outgoing data", 
                                       __FUNCTION__, __LINE__);
                or_mutex_lock(cktData->orOutGngQLock);
                or_mem_free(pnode->data);
                or_util_remove_node_from_list(cktData->orOutGngDataQh,
                                                   OrOutgoingCktData, pnode);
                or_mutex_unlock(cktData->orOutGngQLock);
            }
        }//end if(pnode != NULL)
        else {
            OrDlyTolerantData *dnode = cktData->orDlyTolrntDataQh;
            OrUint8 nNodesInQ = 0;

            printf("cktData : %p\n", cktData);

            while(dnode != NULL) {
                nNodesInQ++;
                dnode = dnode->next;
            }

            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
               "No of nodes in delay tolerant Q: %u", 
            __FUNCTION__, __LINE__, nNodesInQ);

            if(nNodesInQ > 0) {
                dnode = cktData->orDlyTolrntDataQh;
                /* pick up eligible node */
                while(dnode != NULL) {
                    if(dnode->fire == TRUE) {
                        break;
                    }
                    dnode = dnode->next;
                }

                if(dnode != NULL) {
                    if(dnode->data != 0 && dnode->dataL > 0 && dnode->fire) {
                        OrInt nbytes = 0;
                        or_mutex_lock(cktData->orRouterSndRcvLock);
                        /* send data */
                        printf("Sending fired mix message\n");
                        nbytes = write(clientFd, dnode->data, dnode->dataL);
                        or_mutex_unlock(cktData->orRouterSndRcvLock);

                        if(nbytes < dnode->dataL) {
                            dnode->dataL -= nbytes;
                            or_mem_copy(dnode->data, &dnode->data[nbytes], dnode->dataL);
                        }
                        else {
                            or_mutex_lock(cktData->orDlyTolerantQLock);
                            or_mutex_lock(orMixPoolLock);
                            or_mem_free(dnode->data);
                            or_util_remove_node_from_list(cktData->orDlyTolrntDataQh,
                                                            OrDlyTolerantData, dnode);
                            or_mutex_unlock(orMixPoolLock);
                            or_mutex_unlock(cktData->orDlyTolerantQLock);
                        }
                    }
                    else {
                        if((dnode->data == NULL || dnode->dataL == 0)
                            && dnode->fire) {
                            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                                       "Deleting node with invalid dly "
                                                       "tolerant data", 
                                                       __FUNCTION__, __LINE__);
                            or_mutex_lock(cktData->orDlyTolerantQLock);
                            or_mutex_lock(orMixPoolLock);
                            or_mem_free(dnode->data);
                            or_util_remove_node_from_list(cktData->orDlyTolrntDataQh,
                                                               OrDlyTolerantData, dnode);
                            or_mutex_unlock(orMixPoolLock);
                            or_mutex_unlock(cktData->orDlyTolerantQLock);
                        }
                    }//end if(dnode->data != 0 && dnode->dataL > 0 && dnode->fire)
                }//end if(dnode != NULL)
            }//end if(nNodesInQ > 0)
        }//end if(pnode != NULL)
    }//end while
}

static void * or_router_timer_thread(void *thread_param)
{
    OrOnionListNode *onionNode = (OrOnionListNode *) thread_param;
    OrOnionListNode *expdOnion = NULL;
    OrBool isTimeOut = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((onionNode == NULL), 
                    "or_router_timer_thread> onionNode is NULL\n");

    /* TBD: leep for 10 min an then check again for expiry */
    while(or_is_timeout(onionNode->orTimer, &isTimeOut)
        && (isTimeOut == FALSE)) {sleep(1800);}

    OR_ASSERT((isTimeOut == FALSE),
                "or_router_timer_thread>Immature timeout\n");

    expdOnion = (OrOnionListNode *)or_mem_alloc(sizeof(OrOnionListNode));
    OR_ASSERT((expdOnion == NULL), 
                    "or_router_handler> mem alloc failed\n");
    or_mem_set(expdOnion, 0x00, (sizeof(OrOnionListNode)));
    expdOnion->onion.orOnion = (OrUint8 *)or_mem_alloc(onionNode->onion.orLen);
    OR_ASSERT((expdOnion->onion.orOnion == NULL), 
                    "or_router_handler> mem alloc failed\n");
    /* copy onion */
    or_mem_copy(expdOnion->onion.orOnion, onionNode->onion.orOnion, onionNode->onion.orLen);
    expdOnion->onion.orLen = onionNode->onion.orLen;

    or_mutex_lock(orExpdOnionListLock);
    or_util_add_to_list(orExpdOnionList, OrOnionListNode, expdOnion);
    or_mutex_unlock(orExpdOnionListLock);

    or_mem_free(onionNode->onion.orOnion);
    or_mutex_lock(orUnExpdOnionListLock);
    or_util_remove_node_from_list(orUnExpdOnionList, OrOnionListNode, onionNode);
    or_mutex_unlock(orUnExpdOnionListLock);

    pthread_exit(NULL);
}

/*-------------------------Public Fn Defn-----------------------*/
void or_router_init()
{
    OrUint8 itr;
    OrDlyTolerantData *pnode = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT(!or_mutex_create(&orExpdOnionListLock), 
                    "or_router_init> mutex create failed\n");
    OR_ASSERT(!or_mutex_create(&orUnExpdOnionListLock), 
                    "or_router_init> mutex create failed\n");
    OR_ASSERT(!or_mutex_create(&orFwdPathLock), 
                    "or_router_init> mutex create failed\n");
    OR_ASSERT(!or_mutex_create(&orMixPoolLock), 
                    "or_router_init> mutex create failed\n");

    OR_INIT_Q(orAvlblVcId);

    for(itr = 1; itr <= OR_ROUTER_MAX_AVLBL_VCS; itr++) {
        OR_Q_PUT(orAvlblVcId, itr);
    }

    /* Initialize Mix pool */
    for(itr = 0; itr < OR_MIX_PARAM_N; itr++) {
        pnode = (OrDlyTolerantData *) or_mem_alloc(sizeof(OrDlyTolerantData));
        OR_ASSERT((pnode == NULL),"or_router_init> mem alloc failed\n");
        or_mem_set(pnode, 0x00, sizeof(OrDlyTolerantData));
        or_util_add_to_mix_pool(orMixPool, OrDlyTolerantData, pnode);
    }
}

void or_router_handler(OrInt fd,
            const OrUint8 *data,
                OrUint16 length)
{
    or_mutex_lock(orFwdPathLock);
    OrIncmingDataTuple iTuple;
    OrUint8 i = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u", 
                                __FUNCTION__, __LINE__, length);

    iTuple.pLoad  = NULL;
    iTuple.pLoadL = 0;

    /* parse incoming data */
    if(!or_parse_incoming_data(data, length, &iTuple)) {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                                   "Could not parse incoming data. Ignoring." ,
                                   __FUNCTION__, __LINE__);
        or_mutex_unlock(orFwdPathLock);
        return;
    }

    switch(iTuple.cmd) {
        case OR_DATA_CMD:
        {
            OrCktSpecificData *cktData = NULL;

            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Router(Member id: %u) "
                                         "received data cmd.",
                                        __FUNCTION__, __LINE__, orContext.memberId);

            do {
                OrCktSpecificData *traverse = (OrCktSpecificData *)orCktDataPool;
                while (traverse != NULL) {
                    if((traverse->vcId == iTuple.cid)
                        &&(traverse->fd == fd)){
                        break;
                    }
                    traverse = traverse->next;
                }
                cktData = traverse;
            } while(0);

            if(cktData != NULL) {
                OrUint8 *pkt = NULL;
                OrUint8 z;

                OR_ASSERT((or_mem_cmp(cktData->linkKey, iTuple.linkKey, OR_DH_SECRET_LENGTH)),
                        "or_router_handler> Link key doesn't match after " 
                        "challenge decyption\n");

                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> OR router "
                                        "received data cmd from "
                                        "(vc %u)", __FUNCTION__, __LINE__,
                                        cktData->vcId);

                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Payload "
                                        "before decryption "
                                        , __FUNCTION__, __LINE__);

                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
                for(z = 0; z < iTuple.pLoadL; z++) {
                    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ",iTuple.pLoad[z]);
                }
                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
                /* crypt pload using backF */
                or_router_crypt_data(cktData, &iTuple, OR_CRYPTO_DIR_FWD);

                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Payload "
                                        "after decryption "
                                        , __FUNCTION__, __LINE__);

                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
                for(z = 0; z < iTuple.pLoadL; z++) {
                    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ",iTuple.pLoad[z]);
                }
                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

                OR_ASSERT((cktData->pldType != iTuple.pLoadT), 
                                        "Payload type of incoming data does not "
                                        "match with the payload tpe of the rele-"
                                        "vant circuit\n");

                if(iTuple.pLoadT == OR_PAYLOAD_DELAY_TOLERANT_T) {
                    /* put it into a MIX (n+s pool mix) pool */
                    /* form an or pkt */
                    if(or_create_or_pkt(cktData->nextHopLinkKey, cktData->nextHopVcId, OR_DATA_CMD,
                        iTuple.pLoadT, iTuple.pLoad, iTuple.pLoadL,
                        iTuple.mac, &pkt))
                    {
                        OrDlyTolerantData *pnode = NULL;
                        OR_ASSERT((pkt == NULL), 
                            "or_router_handler> or pkt create failed\n");

                        pnode = (OrDlyTolerantData *) or_mem_alloc(sizeof(OrDlyTolerantData));
                        OR_ASSERT((pnode == NULL),"or_router_handler> mem alloc failed\n");
                        or_mem_set(pnode, 0x00, sizeof(OrDlyTolerantData));
                        pnode->data  = pkt;
                        pnode->dataL = OR_PKT_LEN;
                        pnode->rfnceToCktData = cktData;

                        /* put node in outgoing delay tolerant data Q */
                        or_mutex_lock(cktData->orDlyTolerantQLock);
                        or_mutex_lock(orMixPoolLock);
                        or_util_add_to_list_head(cktData->orDlyTolrntDataQh,
                                                            OrDlyTolerantData, pnode);
                        or_util_add_to_mix_pool(orMixPool, OrDlyTolerantData, pnode);
                        or_mutex_unlock(orMixPoolLock);
                        or_mutex_unlock(cktData->orDlyTolerantQLock);

                        /* check can the mix fire. MIX fires s msgs
                         * chosen at random, if n+s mesgs accumulates */
                        /* later we will improve s as s = nP(n).*/
                        or_router_fire_mix_if_possible();
                    }
                    else {
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                         "OR pkt formation failed!!! ",
                                             __FUNCTION__, __LINE__);
                    }// end if(or_create_or_pkt()
                }
                else {
                    /* form an or pkt */
                    if(or_create_or_pkt(cktData->nextHopLinkKey, cktData->nextHopVcId, OR_DATA_CMD,
                        iTuple.pLoadT, iTuple.pLoad, iTuple.pLoadL,
                        iTuple.mac, &pkt))
                    {
                        OrOutgoingCktData *pnode = NULL;
                        OR_ASSERT((pkt == NULL), 
                            "or_router_handler> or pkt create failed\n");

                        pnode = (OrOutgoingCktData *) or_mem_alloc(sizeof(OrOutgoingCktData));
                        OR_ASSERT((pnode == NULL),"or_router_handler> mem alloc failed\n");
                        or_mem_set(pnode, 0x00, sizeof(OrOutgoingCktData));
                        pnode->data  = pkt;
                        pnode->dataL = OR_PKT_LEN;

                        /* put node in outgoing data Q */
                        or_mutex_lock(cktData->orOutGngQLock);
                        or_util_add_to_list_head(cktData->orOutGngDataQh,
                                                    OrOutgoingCktData, pnode);
                        or_mutex_unlock(cktData->orOutGngQLock);

                        /* pass message to forward link */
                        /* signal send thread */
                        OR_ASSERT(!or_sema_release(&cktData->orRouterSndSema),
                                                    "Sema release failed!!!\n");
                    }
                    else {
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                         "OR pkt formation failed!!! ",
                                             __FUNCTION__, __LINE__);
                    }// end if(or_create_or_pkt()
                }//end if(iTuple.pLoadT == OR_PAYLOAD_DELAY_TOLERANT_T)
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                 "OR_DATA_CMD rcvd in unknown ckt!!! Ignoring."
                                                    ,__FUNCTION__, __LINE__);
            }
        }
        break;
        case OR_CREATE_CMD:
        {
            OrCktSpecificData *cktDataNode = NULL;
            OrOnionListNode     *onionNode = NULL;
            OrUint8 decptdOnionLayer[OR_ONION_LAYER_LEN];
            OrUint8 linkKeyOnionLayer[OR_DH_SECRET_LENGTH]; /* link key to 
                                                               decrypt onion layer*/
            OrBool deletenodes = FALSE;

            if(or_is_replayed_onion(&iTuple, orUnExpdOnionList,
                orExpdOnionList, orUnExpdOnionListLock,
                orExpdOnionListLock)) {
                OrUint8 z;
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> It is a replayed "
                                        "onion!!! Ignoring."
                                        ,__FUNCTION__, __LINE__);

                OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %d)> The "
                                          "replayed onion (prepended "
                                          " with 9 byte challenge) is: ",
                                            __FUNCTION__, __LINE__);

                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
                for(z = 0; z < iTuple.pLoadL; z++) {
                    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ",iTuple.pLoad[z]);
                }
                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");

                or_mem_free(iTuple.pLoad);
                or_mutex_unlock(orFwdPathLock);
                return;
            }

            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Router(Member id: %u) "
                                         "received create cmd.",
                                        __FUNCTION__, __LINE__, orContext.memberId);
            /* create ckt pool data */
            cktDataNode = (OrCktSpecificData *) or_mem_alloc(sizeof(OrCktSpecificData));
            OR_ASSERT((cktDataNode == NULL), 
                            "or_router_handler> mem alloc failed\n");
            or_mem_set(cktDataNode, 0x00, (sizeof(OrCktSpecificData)));
            /* postpone allocating memory for onion until challenge decryption */

            /* fill in ckt data except for onion.
             * we will wait for the onion layer
             * parsing to happen for filling the 
             * onion */
            cktDataNode->vcId    = iTuple.cid;
            cktDataNode->fd      = fd;
            cktDataNode->pldType = iTuple.pLoadT;
            or_mem_copy(cktDataNode->linkKey, iTuple.linkKey, OR_DH_SECRET_LENGTH);
            or_mem_set(cktDataNode->nextHopLinkKey, 0x00, OR_DH_SECRET_LENGTH);

            if(iTuple.pLoad != NULL && iTuple.pLoadL != 0) {
                OrUint8 z;
                OR_LOG(OR_LOG_LEVEL_DEBUG,"<%s (Line: %d)> "
                                          "The onion (prepended "
                                          " with 9 byte challenge)is: ",
                                            __FUNCTION__, __LINE__);

                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\t");
                for(z = 0; z < iTuple.pLoadL; z++) {
                    OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "%x ",iTuple.pLoad[z]);
                }
                OR_LOG_NO_EOL(OR_LOG_LEVEL_DEBUG, "\n");
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                            "Onion missing in incoming data "
                            "Ignoring Create Cmd "
                            ,__FUNCTION__, __LINE__);
                deletenodes = TRUE;
                goto PRUNE_N_OUT;
            }

            /* decrypt challenge and get link key */
            if(!or_decrypt_challenge_n_get_link_key(iTuple.pLoad,
                                                   iTuple.pLoadL, 
                                                   linkKeyOnionLayer)) {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                            "Onion Layer challenge could "
                                            "not be decrypted. Ignoring Onion"
                                            ,__FUNCTION__, __LINE__);
                deletenodes = TRUE;
                goto PRUNE_N_OUT;
            }

            /* create onion node for expd/unexpd list */
            onionNode = (OrOnionListNode *) or_mem_alloc(sizeof(OrOnionListNode));
            OR_ASSERT((onionNode == NULL), 
                            "or_router_handler> mem alloc failed\n");
            or_mem_set(onionNode, 0x00, (sizeof(OrOnionListNode)));
            onionNode->onion.orOnion = (OrUint8 *)or_mem_alloc(iTuple.pLoadL);
            OR_ASSERT((onionNode->onion.orOnion == NULL), 
                            "or_router_handler> mem alloc failed\n");
            or_mem_set(onionNode->onion.orOnion, 0x00, iTuple.pLoadL);

            /* copy onion */
            or_mem_copy(onionNode->onion.orOnion, iTuple.pLoad, iTuple.pLoadL);
            onionNode->onion.orLen = iTuple.pLoadL;
            or_mem_copy(onionNode->onion.mac, iTuple.mac, OR_MAC_SIZE);

            /* Allocate memory for onion in ckt data */
            cktDataNode->onion.orOnion = (OrUint8 *)or_mem_alloc(iTuple.pLoadL);
            OR_ASSERT((cktDataNode->onion.orOnion == NULL), 
                            "or_router_handler> mem alloc failed\n");
            or_mem_set(cktDataNode->onion.orOnion, 0x00, iTuple.pLoadL);

            /* copy onion to ckt data */
            or_mem_copy(cktDataNode->onion.orOnion, iTuple.pLoad, iTuple.pLoadL);
            cktDataNode->onion.orLen = iTuple.pLoadL;
            or_mem_copy(cktDataNode->onion.mac, iTuple.mac, OR_MAC_SIZE);

            /* decrypt onion layer */
            or_decrypt_onion_layer(&onionNode->onion, decptdOnionLayer, linkKeyOnionLayer);

            /* parse data & retrieve onion */
            or_router_parse_onion_layer(decptdOnionLayer + OR_CHALLENGE_LEN, cktDataNode);

            /* Find next member in neighbor table */
            for(i = 0; 
            i < orContext.neigborTable.noOfEntriesInNeighborTable; 
            i++) {
                if(orContext.neigborTable.orNeighbor[i].memberId
                    == cktDataNode->layerInfo.nextmemberId) {
                    break;
                }
            }

            if(i != orContext.neigborTable.noOfEntriesInNeighborTable) {
                OrDestAddress nextHopAddr;
                OrNeighborTable *nbrTbl = &orContext.neigborTable;

                or_mem_copy(nextHopAddr.ip, nbrTbl->orNeighbor[i].ip,
                                                  OR_IP_ADDRESS_LENGTH);
                nextHopAddr.port = nbrTbl->orNeighbor[i].port;
                or_mem_copy(cktDataNode->nextHopLinkKey, 
                            nbrTbl->orNeighbor[i].orDhSecret, OR_DH_SECRET_LENGTH);

                if(or_connect_to_remote_server(&cktDataNode->nextHopFd, 
                   nextHopAddr.ip,
                   nextHopAddr.port,
                   OR_HOST_IP)) {
                    /* Assign VC id */
                    if(!OR_IS_Q_EMPTY(orAvlblVcId)) {
                        OrInt nBytes = 0;
                        OrUint8 *pkt = NULL;

                        OR_Q_GET(orAvlblVcId, cktDataNode->nextHopVcId);
                        /* form a or pkt with the peeled onion*/
                        if(or_create_or_pkt(cktDataNode->nextHopLinkKey, 
                            cktDataNode->nextHopVcId, OR_CREATE_CMD,
                            cktDataNode->pldType, cktDataNode->onion.orOnion + OR_ONION_LAYER_LEN,
                            cktDataNode->onion.orLen - OR_ONION_LAYER_LEN,
                            cktDataNode->onion.mac, &pkt))
                        {
                            nBytes = write(cktDataNode->nextHopFd, pkt, OR_PKT_LEN);
                            if(nBytes == OR_PKT_LEN) {
                                OrUint8 tempBuf[1520];

                                nBytes = 0;
                                //nBytes = recv(cktDataNode->nextHopFd, tempBuf, sizeof(tempBuf), MSG_WAITALL);
                                nBytes = recv(cktDataNode->nextHopFd, tempBuf, sizeof(tempBuf), 0);

                                if(nBytes > 0) {
                                    tempBuf[nBytes] = '\0';
                                    if(!strcmp(tempBuf, "success")) {
                                        /* Create Mutex */
                                        OR_ASSERT(!or_mutex_create(&cktDataNode->orRouterSndRcvLock),
                                                                "Mutex create failed\n");
                                        OR_ASSERT(!or_mutex_create(&cktDataNode->orOutGngQLock), 
                                                                "Mutex create failed\n");
                                        OR_ASSERT(!or_mutex_create(&cktDataNode->orDlyTolerantQLock), 
                                                                "Mutex create failed\n");
                                        /* create semaphore */
                                        OR_ASSERT(!or_sema_create(&cktDataNode->orRouterSndSema),
                                                                "Sema create failed\n");
                                        /* create receive thread */
                                        OR_ASSERT((CREATE_THREAD(&cktDataNode->orRouterRcvThread, 
                                            NULL, or_router_rcv_thread, 
                                            cktDataNode) < 0), 
                                            "or_router_handler> create thread failed\n");
                                            /* create send thread */
                                        OR_ASSERT((CREATE_THREAD(&cktDataNode->orRouterSndThread, 
                                            NULL, or_router_snd_thread, 
                                            cktDataNode) < 0),
                                            "or_router_handler> create thread failed\n");

                                        strncpy(tempBuf, "success", 7);
                                        or_sock_write_req(fd, tempBuf, 7);
                                    }
                                    else {
                                        deletenodes = TRUE;
                                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                                                    "remote sent failure"
                                                                    ,__FUNCTION__, __LINE__);
                                    }
                                }
                                else {
                                    deletenodes = TRUE;
                                    close(cktDataNode->nextHopFd);
                                    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> "
                                    "Invalid read: %d!!!", 
                                    __FUNCTION__, __LINE__, nBytes);
                                }
                            }
                            else {
                                deletenodes = TRUE;
                                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> onion "
                                                            "not sent to next hop"
                                                            ,__FUNCTION__, __LINE__);
                            }
                        }
                        else {
                            deletenodes = TRUE;
                            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> or pkt "
                                                        "could not be formed"
                                                        ,__FUNCTION__, __LINE__);
                        }
                        or_mem_free(pkt);
                    }
                    else {
                        deletenodes = TRUE;
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> ckt id unavailable"
                                                    ,__FUNCTION__, __LINE__);
                    }
                }
                else {
                    deletenodes = TRUE;
                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Could not " 
                                                "connect to next member (id: %u)",
                                                __FUNCTION__, __LINE__, 
                                                cktDataNode->layerInfo.nextmemberId);
                }
            }
            else {
                deletenodes = TRUE;
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> next member (id: %u) "
                                             "not found in neighbor table"
                                            ,__FUNCTION__, __LINE__, 
                                            cktDataNode->layerInfo.nextmemberId);
            }

PRUNE_N_OUT:
            if(deletenodes == TRUE) {
                if(onionNode != NULL) {
                    or_mem_free(onionNode->onion.orOnion);
                }
                or_mem_free(onionNode);
                if(cktDataNode != NULL) {
                    or_mem_free(cktDataNode->onion.orOnion);
                }
                or_mem_free(cktDataNode);
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Deleting nodes. "
                             "Ignoring incoming data"
                            ,__FUNCTION__, __LINE__);
            }
            else {
                /* create timer */
                onionNode->orTimer =  or_time_init_timer(cktDataNode->layerInfo.expTime,
                                                OR_TIME_IN_SEC_T);
                OR_ASSERT((CREATE_THREAD(&onionNode->orTimerThd, 
                    NULL, or_router_timer_thread, 
                    onionNode) < 0), 
                    "or_router_handler> create thread failed!!!\n");

                /* save onion in unexpd onion list */
                or_mutex_lock(orUnExpdOnionListLock);
                or_util_add_to_list(orUnExpdOnionList, OrOnionListNode, onionNode);
                or_mutex_unlock(orUnExpdOnionListLock);

                /* add ckt specific data ckt data pool */
                or_util_add_to_list(orCktDataPool, OrCktSpecificData, cktDataNode);
            }
        }
        break;
        case OR_DESTROY_CMD:
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Router(Member id: %u) "
                                         "received destroy cmd.",
                                        __FUNCTION__, __LINE__, orContext.memberId);
        }
        break;
        case OR_PADDING_CMD:
        {
            OrCktSpecificData *cktData = NULL;

            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Router "
                                        "(Member id: %u) "
                                         "received padding cmd.",
                                        __FUNCTION__, __LINE__, orContext.memberId);

            do {
                OrCktSpecificData *traverse = (OrCktSpecificData *)orCktDataPool;
                while (traverse != NULL) {
                    if((traverse->vcId == iTuple.cid)
                        &&(traverse->fd == fd)){
                        break;
                    }
                    traverse = traverse->next;
                }
                cktData = traverse;
            } while(0);

            if(cktData != NULL) {
                OrUint8 *pkt = NULL;

                OR_ASSERT((or_mem_cmp(cktData->linkKey, iTuple.linkKey, OR_DH_SECRET_LENGTH)),
                        "or_router_handler> Link key doesn't match after " 
                        "challenge decyption\n");

                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> OR router "
                                        "received padding cmd.from "
                                        "(vc %u)", __FUNCTION__, __LINE__,
                                        cktData->vcId);

                OR_ASSERT((cktData->pldType != iTuple.pLoadT), 
                        "Payload type of incoming data does not "
                        "match with the payload tpe of the rele-"
                        "vant circuit\n");

                if(iTuple.pLoadT == OR_PAYLOAD_DELAY_TOLERANT_T) {
                    /* put it into a MIX (n+s pool mix) pool */
                    /* form an or pkt */
                    if(or_create_or_pkt(cktData->nextHopLinkKey, 
                        cktData->nextHopVcId, OR_PADDING_CMD,
                        iTuple.pLoadT, iTuple.pLoad, iTuple.pLoadL,
                        iTuple.mac, &pkt))
                    {
                        OrDlyTolerantData *pnode = NULL;
                        OR_ASSERT((pkt == NULL), 
                            "or_router_handler> or pkt create failed\n");

                        pnode = (OrDlyTolerantData *) or_mem_alloc(sizeof(OrDlyTolerantData));
                        OR_ASSERT((pnode == NULL),"or_router_handler> mem alloc failed\n");
                        or_mem_set(pnode, 0x00, sizeof(OrDlyTolerantData));
                        pnode->data  = pkt;
                        pnode->dataL = OR_PKT_LEN;
                        pnode->rfnceToCktData = cktData;

                        /* put node in outgoing delay tolerant data Q */
                        or_mutex_lock(cktData->orDlyTolerantQLock);
                        or_mutex_lock(orMixPoolLock);
                        or_util_add_to_list_head(cktData->orDlyTolrntDataQh,
                                                            OrDlyTolerantData, pnode);
                        or_util_add_to_mix_pool(orMixPool, OrDlyTolerantData, pnode);
                        or_mutex_unlock(orMixPoolLock);
                        or_mutex_unlock(cktData->orDlyTolerantQLock);

                        /* check can the mix fire. MIX fires s msgs
                         * chosen at random, if n+s mesgs accumulates */
                        /* later we will improve s as s = nP(n).*/
                        or_router_fire_mix_if_possible();
                    }
                    else {
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                         "OR pkt formation failed!!! ",
                                             __FUNCTION__, __LINE__);
                    }// end if(or_create_or_pkt()
                }
                else {
                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                     "Ignoring padding cmd. Invalid payload type %u.",
                                    __FUNCTION__, __LINE__, iTuple.pLoadT);
                }
            }
            else {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                 "OR_PADDING_CMD rcvd in unknown ckt!!! Ignoring."
                                            ,__FUNCTION__, __LINE__);
            }
        }
        break;
        default:
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Unhandled cmd "
                                         "%u. Ignoring data",
                                        __FUNCTION__, __LINE__, iTuple.cmd);
        }
        break;
    }

    or_mem_free(iTuple.pLoad);
    or_mutex_unlock(orFwdPathLock);
}

void or_router_deinit()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mutex_destroy(orExpdOnionListLock);
    or_mutex_destroy(orUnExpdOnionListLock);
    or_mutex_destroy(orFwdPathLock);
    or_mutex_destroy(orMixPoolLock);
    /*TBD: destroy expd onion list */
    /*TBD: destroy unexpd onion list */
    /*TBD: destroy ckt pool */

    OR_Q_DESTROY(orAvlblVcId);
}
