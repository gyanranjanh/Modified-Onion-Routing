/*
 * FILE:	or_exit_funnel.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_exit_funnel.h"
#include "or_util.h"
#include "or_time.h"
#include "or_common.h"
#include "or_log.h"
#include "or_security_module.h"

/*------------------------Local Variables & Data----------------*/
static OrOnionList           *orExpdOnionList = NULL;
static OrOnionList         *orUnExpdOnionList = NULL;
static OrMutexHandle     orExpdOnionListLock = NULL;
static OrMutexHandle   orUnExpdOnionListLock = NULL;
static OrMutexHandle           orFwdPathLock = NULL;
static OrRegdRcvrPool          *orRgdRcvrPool = NULL;
static OrPendingVcList      *orPendingVcListH = NULL;

OR_CREATE_Q(OrUint8, orAvlblSesnId);

/*-----------------------Local Fn Decn--------------------------*/
static void or_exit_funnel_crypt_data(const OrRcvCktSpcfcData *cktData,
                                      OrOutGoingData  *oData,
                                      OrCryptoDir cryptoDir);
static void or_exit_funnel_parse_onion_layer(const OrUint8 *decptdOnionLayer, 
                                             OrRcvCktSpcfcData *cktData);
static OrBool or_exit_funnel_does_vcid_exist(OrUint8 sesnId, OrRegdRcvr *regdRcvr,
                                            OrRcvCktSpcfcData **cktData);
static void * or_exit_funnel_timer_thread(void *thread_param);


/*-----------------------Local Fn Defn--------------------------*/
static void or_exit_funnel_crypt_data(const OrRcvCktSpcfcData *cktData,
                                      OrCktData *cData,
                                      OrCryptoDir cryptoDir)
{
    const OrUint8   *key = NULL;
    OrUint8 n = 0, m = 0, k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", 
                                    __FUNCTION__, __LINE__);

    OR_ASSERT((cktData == NULL), "Invalid ckt data\n");
    OR_ASSERT((cData == NULL), "Invalid data\n");


    m = cData->dataL / OR_FORW_BACK_KEY_LENGTH;
    n = cData->dataL % OR_FORW_BACK_KEY_LENGTH;

    if(cryptoDir == OR_CRYPTO_DIR_BCK){
        key = cktData->layerInfo.orBackFkey;
    }
    else {
        key = cktData->layerInfo.orForwFkey;
    }

    OR_XOR_FORW_BACK_KEY_N_TIMES(cData->data, key, m);
    OR_XOR_FORW_BACK_KEY_N_BYTES(cData->data + m * OR_FORW_BACK_KEY_LENGTH, key, n);
}

static void or_exit_funnel_parse_onion_layer(const OrUint8 *decptdOnionLayer, 
                                             OrRcvCktSpcfcData *cktData)
{
    const OrUint8 *pdata = decptdOnionLayer;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((decptdOnionLayer == NULL), 
        "or_exit_funnel_parse_onion_layer> decptdOnionLayr is NULL\n");
    OR_ASSERT((cktData == NULL), 
        "or_exit_funnel_parse_onion_layer> cktData is NULL\n");

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

    cktData->layerInfo.backF = pdata[0];
    pdata += OR_BACK_F_LEN;
    cktData->layerInfo.forwF = pdata[0];
    pdata += OR_FORW_F_LEN;
    cktData->layerInfo.nextmemberId = 
                    OR_GET_UINT16_FROM_LITTLE_ENDIAN(pdata);
    OR_ASSERT((cktData->layerInfo.nextmemberId != OR_INVALID_MEMBER_ID),
            "or_exit_funnel_parse_onion_layer> exit funnel rcvd onion "
            "with undesired next hop info.");
    pdata += OR_MEMBER_ID_LEN;
    or_mem_copy((void *)cktData->layerInfo.orBackFkey,
                            (void *)pdata, OR_FORW_BACK_KEY_LENGTH);
    pdata += OR_FORW_BACK_KEY_LENGTH;
    or_mem_copy((void *)cktData->layerInfo.orForwFkey,
                            (void *)pdata, OR_FORW_BACK_KEY_LENGTH);
    pdata += OR_FORW_BACK_KEY_LENGTH;
    cktData->layerInfo.expTime = OR_GET_UINT32_FROM_LITTLE_ENDIAN(pdata);
}

static OrBool or_exit_funnel_does_vcid_exist(OrUint8 sesnId,
                                       OrRegdRcvr *regdRcvr,
                                OrRcvCktSpcfcData **cktData)
{
    OrBool    result = FALSE;
    OrUint8        k = 0;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    if(regdRcvr != NULL) {
        for(; k < regdRcvr->nSesns; k++) {
            if(sesnId == regdRcvr->rcvCktData[k].sesnId) {
                break;
            }
        }

        if(k != regdRcvr->nSesns) {
            *cktData = &regdRcvr->rcvCktData[k];
             result  = TRUE;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<",
                                __FUNCTION__, __LINE__, result);

    return result;
}

static void * or_exit_funnel_timer_thread(void *thread_param)
{
    OrOnionListNode *onionNode = (OrOnionListNode *) thread_param;
    OrOnionListNode *expdOnion = NULL;
    OrBool isTimeOut = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT((onionNode == NULL), 
                "or_exit_funnel_timer_thread> onionNode is NULL\n");

    /* TBD: leep for 10 min an then check again for expiry */
    while(or_is_timeout(onionNode->orTimer, &isTimeOut)
        && (isTimeOut == FALSE)) {sleep(600);}

    OR_ASSERT((isTimeOut == FALSE),
                "or_exit_funnel_timer_thread> Immature timeout\n");

    expdOnion = (OrOnionListNode *)or_mem_alloc(sizeof(OrOnionListNode));
    OR_ASSERT((expdOnion == NULL), 
                    "or_exit_funnel_timer_thread> mem alloc failed\n");
    or_mem_set(expdOnion, 0x00, (sizeof(OrOnionListNode)));
    expdOnion->onion.orOnion = (OrUint8 *)or_mem_alloc(onionNode->onion.orLen);
    OR_ASSERT((expdOnion->onion.orOnion == NULL), 
                    "or_exit_funnel_timer_thread> mem alloc failed\n");

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

/*-----------------------Global Fn Defn-------------------------*/

void or_exit_funnel_init()
{
    OrUint8 itr;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT(!or_mutex_create(&orExpdOnionListLock), 
                    "or_exit_funnel_init> mutex create failed\n");
    OR_ASSERT(!or_mutex_create(&orUnExpdOnionListLock), 
                    "or_exit_funnel_init> mutex create failed\n");
    OR_ASSERT(!or_mutex_create(&orFwdPathLock), 
                    "or_exit_funnel_init> mutex create failed\n");

    OR_INIT_Q(orAvlblSesnId);

    /* Add ids to the Q */
    for(itr = 1; itr <= OR_ONION_PROXY_MAX_SESSION; itr++) {
        OR_Q_PUT(orAvlblSesnId, itr);
    }
}

void or_exit_funnel_handler(OrInt fd,
                 const OrUint8 *data,
                     OrUint16 length)
{
    or_mutex_lock(orFwdPathLock);
    OrIncmingDataTuple iTuple;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mem_set(&iTuple, 0x00, sizeof(OrIncmingDataTuple));

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
            OrPendingVcNode    *vcNode = NULL;
            OrRegdRcvr       *regdRcvr = NULL;
            OrRcvCktSpcfcData *cktData = NULL;
            OrUint8 z;

            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Exit funnel "
                                            "rcvd data cmd in vc %u"
                                        ,__FUNCTION__, __LINE__, iTuple.cid);

            /* is the vcid in the pending vc list */
             do {
                OrPendingVcNode *traverse = (OrPendingVcNode *)orPendingVcListH;
                while (traverse != NULL) {
                    if((traverse->cktData.vcId == iTuple.cid)
                        && (traverse->cktData.fd == fd)){
                        break;
                    }
                    traverse = traverse->next;
                }
                vcNode = traverse;
            } while(0);

            if(vcNode == NULL) {
                /* if it is not in pending vc list then 
                 * it must be a known vc for one of the
                 * registered receivers */
                do {
                    OrRegdRcvr *traverse = (OrRegdRcvr *)orRgdRcvrPool;
                    while (traverse != NULL) {
                        for(z = 0; z < traverse->nSesns; z++) {
                            if((traverse->rcvCktData[z].vcId == iTuple.cid)
                                && (traverse->rcvCktData[z].fd == fd)){
                                break;
                            }
                        }
                        if(z != traverse->nSesns) {
                            break;
                        }
                        traverse = traverse->next;
                    }
                    regdRcvr = traverse;
                } while(0);

                if(regdRcvr == NULL) {
                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                          "No matching ckt found at exit funnel. "
                          "Ignoring data cmd", __FUNCTION__, __LINE__);
                    or_mem_free(iTuple.pLoad);
                    or_mutex_unlock(orFwdPathLock);
                    return;
                }
            }
            else {
                /* After parsing the data we should know for which member the 
                 * the VC is */
            }

            if(vcNode !=  NULL) {
                cktData = &vcNode->cktData;
            }
            else {
                if(regdRcvr != NULL) {
                    cktData = &regdRcvr->rcvCktData[z];
                }
            }

            if(cktData != NULL) {
                OrUint8 *pkt = NULL;
                OrCktData cData;

                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Exit Funnel "
                                        "received data cmd in (vc %u).",
                                        __FUNCTION__, __LINE__, cktData->vcId);

                cData.data  = iTuple.pLoad;
                cData.dataL = iTuple.pLoadL;

                /* crypt pload using backF */
                or_exit_funnel_crypt_data(cktData, &cData, OR_CRYPTO_DIR_FWD);

                /* if vcnode is not null look for destination member */
                if(vcNode != NULL) {
                    printf("Test: %s\n", cData.data);
                    if(!strcmp(cData.data, "memberid: ")) {
                         OrUint8 memberId = OR_GET_UINT16_FROM_LITTLE_ENDIAN(
                                                        &cData.data[strlen(cData.data) + 1]);
                         printf("Incoming data has member id: %u\n", memberId);
                        /* find the destination regd rcvr */
                        do {
                            OrRegdRcvr *traverse = orRgdRcvrPool;
                            while (traverse != NULL) {
                                if((traverse->memberId == memberId)){
                                    break;
                                }
                                traverse = traverse->next;
                            }
                            regdRcvr = traverse;
                        } while(0);

                        if(regdRcvr == NULL) {
                            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                  "No matching ckt found at exit funnel. "
                                  "Ignoring data cmd", __FUNCTION__, __LINE__);

                            or_mem_free(iTuple.pLoad);
                            or_mutex_unlock(orFwdPathLock);
                            return;
                        }

                        or_mem_copy(&regdRcvr->rcvCktData[regdRcvr->nSesns],
                                                cktData, sizeof(OrRcvCktSpcfcData));
                        regdRcvr->nSesns++;

                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                         "ckt data copied to identified registered "
                         "receiver. To (member id: %u).\n"
                         ,__FUNCTION__, __LINE__, regdRcvr->memberId);

                        /* Now we can remove vcNode from pending vc list */
                        or_util_remove_node_from_list(orPendingVcListH,
                                                    OrPendingVcNode, vcNode);
                    }
                    else {
                        /* member id not allocated for this pending VC */
                        /* waiting for membeId from initiator */
                        OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                          "Exit funnel waiting for member id to assign "
                          "to pending VC. Ignoring data cmd.", __FUNCTION__, __LINE__);
                    }
                }
                else {
                    /* else pass the data to respective member */
                    if(regdRcvr != NULL) {
                        regdRcvr->rcvDataInd(regdRcvr->memberId, cktData->sesnId, 
                                                        (const OrIncomingData *)&cData);
                    }
                    else {
                         OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                          "Pending VC node and corresponding registered "
                          "receiver can not be NULL at the same time. "
                          "Ignoring data cmd.", __FUNCTION__, __LINE__);
                    }
                }
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
            OrPendingVcNode        *vcNode = NULL;
            OrRcvCktSpcfcData     *cktData = NULL;
            OrOnionListNode     *onionNode = NULL;
            OrUint8                   tempbuf[50];
            OrUint8 linkKeyOnionLayer[OR_DH_SECRET_LENGTH]; /* link key to 
                                                               decrypt onion layer*/
            OrUint8 decptdOnionLayer[OR_ONION_LAYER_LEN];
            OrBool deletenodes = FALSE;

            if(or_is_replayed_onion(&iTuple, orUnExpdOnionList,
                orExpdOnionList, orUnExpdOnionListLock,
                orExpdOnionListLock)) {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> It is a replayed "
                                        "onion!!! Ignoring."
                                        ,__FUNCTION__, __LINE__);
                deletenodes = TRUE;
                goto PRUNE_N_OUT;
            }

            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Exit funnel "
                                         "rcvd create cmd in (vc: %u)"
                                        ,__FUNCTION__, __LINE__, iTuple.cid);
            /* create ckt pool data */
            vcNode = (OrPendingVcNode *) or_mem_alloc(sizeof(OrPendingVcNode));
            OR_ASSERT((vcNode == NULL), 
                            "or_exit_funnel_handler> mem alloc failed\n");
            or_mem_set(vcNode, 0x00, (sizeof(OrPendingVcNode)));
            cktData = &vcNode->cktData;

            /* fill in ckt data except for onion.
             * we will wait for the onion layer
             * parsing to happen for filling the 
             * onion */
            cktData->vcId    = iTuple.cid;
            cktData->fd      = fd;
            cktData->pldType = iTuple.pLoadT;
            cktData->sesnId  = OR_RCVR_INVALID_SESN_ID;
            or_mem_copy(cktData->linkKey, iTuple.linkKey, OR_DH_SECRET_LENGTH);

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
            };

            /* decrypt challenge and get link key */
            if(!or_decrypt_challenge_n_get_link_key(iTuple.pLoad,
                                                   iTuple.pLoadL, 
                                                   linkKeyOnionLayer)) {
                OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> "
                                            "Onion Layer challenge could "
                                            "not be decrypted. Ignoring Onion."
                                            ,__FUNCTION__, __LINE__);
                deletenodes = TRUE;
                goto PRUNE_N_OUT;
            }

            /* create onion node for expd/unexpd onion list */
            onionNode = (OrOnionListNode *) or_mem_alloc(sizeof(OrOnionListNode));
            OR_ASSERT((onionNode == NULL), 
                            "or_exit_funnel_handler> mem alloc failed\n");
            or_mem_set(onionNode, 0x00, (sizeof(OrOnionListNode)));
            onionNode->onion.orOnion = (OrUint8 *)or_mem_alloc(iTuple.pLoadL);
            OR_ASSERT((onionNode->onion.orOnion == NULL), 
                            "or_exit_funnel_handler> mem alloc failed\n");
            or_mem_set(onionNode->onion.orOnion, 0x00, iTuple.pLoadL);

            /* copy onion */
            or_mem_copy(onionNode->onion.orOnion, iTuple.pLoad, iTuple.pLoadL);
            onionNode->onion.orLen = iTuple.pLoadL;
            or_mem_copy(onionNode->onion.mac, iTuple.mac, OR_MAC_SIZE);

            /* Allocate memory */
            cktData->onion.orOnion = (OrUint8 *) or_mem_alloc(iTuple.pLoadL);
            OR_ASSERT((cktData->onion.orOnion == NULL), 
                            "or_exit_funnel_handler> mem alloc failed\n");
            or_mem_set(cktData->onion.orOnion, 0x00, iTuple.pLoadL);

            /* copy onion to ckt data */
            or_mem_copy(cktData->onion.orOnion, iTuple.pLoad, iTuple.pLoadL);
            cktData->onion.orLen = iTuple.pLoadL;
            or_mem_copy(cktData->onion.mac, iTuple.mac, OR_MAC_SIZE);


            /* decrypt onion layer */
            or_decrypt_onion_layer(&onionNode->onion, decptdOnionLayer, linkKeyOnionLayer);

            /* parse data & retrieve onion */
            or_exit_funnel_parse_onion_layer(decptdOnionLayer + OR_CHALLENGE_LEN, cktData);

PRUNE_N_OUT:
            if((!OR_IS_Q_EMPTY(orAvlblSesnId)) && (deletenodes == FALSE)) {
                OR_Q_GET(orAvlblSesnId, cktData->sesnId);
                /* create timer */
                onionNode->orTimer = or_time_init_timer(cktData->layerInfo.expTime,
                                                OR_TIME_IN_SEC_T);
                OR_ASSERT((CREATE_THREAD(&onionNode->orTimerThd, 
                    NULL, or_exit_funnel_timer_thread, 
                    onionNode) < 0), 
                    "or_exit_funnel_handler> create thread failed!!!\n");

                /* save onion in unexpd onion list */
                or_mutex_lock(orUnExpdOnionListLock);
                or_util_add_to_list(orUnExpdOnionList, OrOnionListNode, onionNode);
                or_mutex_unlock(orUnExpdOnionListLock);

                /* add vcNode to pending vc list */
                or_util_add_to_list(orPendingVcListH, OrPendingVcNode, vcNode);
                /* send success to waitiing previous hop */
                strncpy(tempbuf, "success", 7);
                or_sock_write_req(fd, tempbuf, 7);
            }
            else {
                if(onionNode != NULL) {
                    or_mem_free(onionNode->onion.orOnion);
                }
                or_mem_free(onionNode);
                if(vcNode != NULL && cktData != NULL) {
                    or_mem_free(cktData->onion.orOnion);
                }
                or_mem_free(vcNode);
                if(OR_IS_Q_EMPTY(orAvlblSesnId)) {
                    OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Sesn id unavilable. "
                                                 "Ignoring incoming data"
                                                ,__FUNCTION__, __LINE__);
                }
            }
        }
        break;
        case OR_DESTROY_CMD:
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Exit funnel "
                                         "received destroy cmd in (vc id: %u)."
                                        ,__FUNCTION__, __LINE__, iTuple.cid);
        }
        break;
        case OR_PADDING_CMD:
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Exit funnel "
                                         "received padding cmd in (vc id: %u). Ignoring"
                                        ,__FUNCTION__, __LINE__, iTuple.cid);
        }
        break;
        default:
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG , "<%s (Line: %d)> Unhandled cmd "
                                         "%u. Ignoring data"
                                        ,__FUNCTION__, __LINE__, iTuple.cmd);
        }
        break;
    }

    or_mem_free(iTuple.pLoad);
    or_mutex_unlock(orFwdPathLock);
}

void or_exit_funnel_register_receiver(OrUint8 memberId,
                                      OrRcvDataInd rcvDataInd)
{
    OrRegdRcvr *node = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    node = (OrRegdRcvr *) or_mem_alloc(sizeof(OrRegdRcvr));

    OR_ASSERT((node == NULL), 
                "or_exit_funnel_register_receiver> mem alloc failed!!!\n");

    or_mem_set(node, 0x00, sizeof(OrRegdRcvr));

    node->memberId   = memberId;
    node->rcvDataInd = rcvDataInd;

    or_util_add_to_list(orRgdRcvrPool, OrRegdRcvr, node);
}

OrBool or_exit_funnel_reply_req(OrUint8 memberId,
                       OrUint8 sesnId,
                       OrOutGoingData *outGngData)
{
    OrRegdRcvr            *node = NULL;
    OrRcvCktSpcfcData  *cktData = NULL;
    OrUint8                *pkt = NULL;
    OrUint8                vcId = 0xff;
    OrUint8 mac[OR_MAC_FLD_LEN] = {0xff};
    OrBool               result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    /* Find member in the regd rcvr pool */
    or_util_find_node_in_list(orRgdRcvrPool, OrRegdRcvr,
                                          memberId, memberId, node);

    if(node != NULL) {
        /* retrieve vcId from sesn Id */
        vcId = sesnId; /* sesnIds are vcIds */
        /* Does vcId exist? */
        if(or_exit_funnel_does_vcid_exist(sesnId, node, &cktData)) {
            /* crypt using corresponfing BFn & key and send */
            or_exit_funnel_crypt_data(cktData, outGngData, OR_CRYPTO_DIR_BCK);
            /* form or pkt */
            if(or_create_or_pkt(cktData->linkKey, cktData->vcId, OR_DATA_CMD, 
                             cktData->pldType, outGngData->data,
                             outGngData->dataL, mac, &pkt)) {
                if(or_sock_write_req(cktData->fd, pkt, OR_PKT_LEN)) {
                    result = TRUE;
                }
            }
            or_mem_free(pkt);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>"
                "or_exit_reply_req> could not find member (id: %u)"
                "in regd. rcvr pool", __FUNCTION__, __LINE__, memberId);
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<",
                            __FUNCTION__, __LINE__, result);

    return result;
}

void or_exit_funnel_deinit()
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    or_mutex_destroy(orExpdOnionListLock);
    or_mutex_destroy(orUnExpdOnionListLock);
    or_mutex_destroy(orFwdPathLock);
    /*TBD: destroy expd onion list */
    /*TBD: destroy unexpd onion list */
    /*TBD: destroy pending vc list */
    /*TBD: destroy registered receiver pool */
}

