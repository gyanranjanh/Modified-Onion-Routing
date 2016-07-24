/*
 * FILE:	or_application_proxy.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */
#include "or_util.h"
#include "or_log.h"
#include "or_common.h"
#include "or_application_proxy.h"

/*----------------------------Local Variables----------------------*/
static OrSessionEntry *orSessionTable = NULL;

/*---------------------------Private Fn Prototype------------------*/
static OrBool or_app_proxy_does_address_match(OrDestAddress a,
                                              OrDestAddress b);
static OrBool or_app_proxy_is_session_ongoing(OrDestAddress dest,
                 OrProtocol proto, OrUint8  *sesnId, OrAppDataInd appDataInd);
static void or_app_proxy_add_new_session_to_table(OrDestAddress dest,
                 OrProtocol proto, OrUint8  sesnId, OrAppDataInd appDataInd);
static void or_app_proxy_delete_existing_session(OrUint8 sesnId);

/*---------------------------Private Fn Defn-----------------------*/
static OrBool or_app_proxy_does_address_match(OrDestAddress a,
                                              OrDestAddress b)
{
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(!or_mem_cmp(a.ip, b.ip, OR_IP_ADDRESS_LENGTH))
    {
        if(a.port == b.port)
        {
            result = TRUE;
        }
        else
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> IP matched but port didn't"
                                                ,__FUNCTION__, __LINE__);
        }
    }
    else
    {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> IP didn't match"
                                            ,__FUNCTION__, __LINE__);
    }

    return result;
}

static OrBool or_app_proxy_is_session_ongoing(OrDestAddress dest,
                                              OrProtocol proto,
                                              OrUint8  *sesnId,
                                              OrAppDataInd appDataInd)
{
    OrSessionEntry *node = orSessionTable;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(sesnId != NULL)
    {
        while(node != NULL) 
        {
            if(or_app_proxy_does_address_match(node->sesnTriplet.dest, dest))
            {
                if(node->sesnTriplet.proto == proto)
                {
                    *sesnId          = node->sesnTriplet.sessionId;
                    if(appDataInd != NULL) {
                        node->appDataInd = appDataInd;
                    }
                    result           = TRUE;
                    break;
                }
            }
            node = node->next;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Session %s", 
                                __FUNCTION__, __LINE__, result ? "found" : "not found ");

    return result;
}

static void or_app_proxy_add_new_session_to_table(OrDestAddress dest,
                                                  OrProtocol proto,
                                                  OrUint8  sesnId,
                                                  OrAppDataInd appDataInd)
{
    OrSessionEntry *node = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    node = (OrSessionEntry *) or_mem_alloc(sizeof(OrSessionEntry));

    node->appDataInd            = appDataInd;
    node->sesnTriplet.dest      = dest;
    node->sesnTriplet.proto     = proto;
    node->sesnTriplet.sessionId = sesnId;
    node->next                  = NULL;

    if(orSessionTable == NULL)
    {
        orSessionTable = node;
    }
    else
    {
        OrSessionEntry *temp = orSessionTable;

        while(temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = node;
    }
}

static void or_app_proxy_delete_existing_session(OrUint8 sesnId)
{
    OrSessionEntry *node = orSessionTable, *prev = orSessionTable;
    OrBool deleted       = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    while(node != NULL)
    {
        if(node->sesnTriplet.sessionId == sesnId)
        {
            break;
        }
        prev = node;
        node = node->next;
    }

    if(node != NULL)
    {
        if(node == orSessionTable)
        {
            orSessionTable = node->next;
        }
        else
        {
            prev->next = node->next;
        }
        or_mem_free(node);
        deleted = TRUE;
    }

    if(deleted)
    {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Session deleted", __FUNCTION__, __LINE__);
    }
    else
    {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Session not found", __FUNCTION__, __LINE__);
    }
}

/*-------------------------------Public Fn Defn----------------------------------*/
void or_app_proxy_init()
{
    /* Initialize onnion proxy module */
    or_onion_proxy_init();
    /* update neighbor table */
    or_onion_proxy_update_neighbor_table_for_member(orContext.memberId,
                                                          &orContext.neigborTable);
}

OrBool or_app_proxy_send_data(OrDestAddress dest,
                              OrProtocol   proto,
                              OrUint8      *data,
                              OrUint16 dataLength,
                              OrAppDataInd appDataInd)
{
    OrUint8 sesnId = OR_INVALID_SESSION_ID;
    OrBool result  = FALSE;

    /* Does a OR session exist with destination? */
    /* if yes,request or-proxy for data transfer */
    /* if no, request or-proxy for a new OR session */

    /* (destination, or_session_id) */

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(or_app_proxy_is_session_ongoing(dest, proto, &sesnId, appDataInd))
    {
        /* Session already exists. Req or-onion-proxy for data */
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                   "Sending data request to onion-proxy in "
                                   "existing session id %d", __FUNCTION__, 
                                   __LINE__, sesnId);

        if(or_onion_proxy_data_req(orContext.memberId, sesnId, data, dataLength))
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> data accepted by or-onion-proxy",
                                                    __FUNCTION__, __LINE__);
            result = TRUE;
        }
    }
    else
    {
        /* Session does not exist. Req for new or-session */
        if(or_onion_proxy_create_or_session_req(orContext.memberId, 
                        dest, proto, or_app_proxy_data_ind, &sesnId))
        {
            OrUint8 temp[50] = {0};
            OrUint8 i;
            OrNeighborTable *nbrtbl = &orContext.neigborTable;

            or_app_proxy_add_new_session_to_table(dest, proto, sesnId, appDataInd);

            for(i = 0; i < nbrtbl->noOfEntriesInNeighborTable; i++) {
                if(!or_mem_cmp(nbrtbl->orNeighbor[i].ip,
                    dest.ip, OR_IP_ADDRESS_LENGTH)
                    && (nbrtbl->orNeighbor[i].port == dest.port)) {
                    break;
                }
            }
            if(i != nbrtbl->noOfEntriesInNeighborTable) {
                strcpy(temp, "memberid: ");
                OR_COPY_UINT16_TO_LITTLE_ENDIAN(nbrtbl->orNeighbor[i].memberId,
                                                         &temp[strlen(temp) + 1]);

                OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                           "Sending %s: 0x%x 0x%x"
                                           " to exit-funnel "
                                           "after vc creation ",
                                           __FUNCTION__, __LINE__, temp,
                                           temp[strlen(temp) + 2], temp[strlen(temp) + 1]);

                /* request data in new session id to onion-proxy */
                if(or_onion_proxy_data_req(orContext.memberId, sesnId, temp, 
                                                               strlen(temp) + 3))
                {
                    /* request data in new session id to onion-proxy */
                    if(or_onion_proxy_data_req(orContext.memberId, sesnId, data, dataLength))
                    {
                        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                                   "data accepted by or-onion-proxy",
                                                   __FUNCTION__, __LINE__);
                        result = TRUE;
                    }
                }
            }
        }
        else
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Or session doesn't "
                                        "exist. Could not create.", __FUNCTION__, __LINE__);
        }
    }

    return result;
}

#ifdef OR_TEST_MODE
OrBool or_app_proxy_send_dummy_msg(OrDestAddress dest)
{
    OrUint8 sesnId = OR_INVALID_SESSION_ID;
    OrBool result  = FALSE;

    /* Does a OR session exist with destination? */
    /* if yes,request or-proxy for dummy msg */

    /* (destination, or_session_id) */

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(or_app_proxy_is_session_ongoing(dest, OR_PROTO_SMTP, &sesnId, NULL))
    {
        /* Session already exists. Req or-onion-proxy for data */
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                   "Sending data request to onion-proxy in "
                                   "existing session id %d", __FUNCTION__, 
                                   __LINE__, sesnId);

        if(or_onion_proxy_dummy_msg_req(orContext.memberId, sesnId))
        {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                        "dummy msg accepted "
                                        " by or-onion-proxy",
                                        __FUNCTION__, __LINE__);
            result = TRUE;
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                            "delay tolerant sessn "
                            "does not exist. Dummy msg not sent.",
                            __FUNCTION__, __LINE__);
    }

    return result;
}
#endif

void or_app_proxy_data_ind(OrUint8 sessionId,
                           OrUint8     *data,
                           OrUint16 dataL)
{
    OrSessionEntry *node = NULL;
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    do {
        OrSessionEntry *traverse = orSessionTable;
        while (traverse != NULL) {
            if(traverse->sesnTriplet.sessionId == sessionId) {
                break;
            }
            traverse = traverse->next;
        }
        node = traverse;
    }while(0);

    if(node == NULL) {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                   "app call back not "
                                   "found for sesion id %u. "
                                   "Discarding data.",
                                   __FUNCTION__, __LINE__, sessionId);
    }
    else {
        node->appDataInd(&node->sesnTriplet, data, dataL);
    }
}

void or_app_proxy_deinit()
{
    or_util_destroy_list(orSessionTable, OrSessionEntry);
    /* deinitialize onion proxy */
    or_onion_proxy_deinit();
}

