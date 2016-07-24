/*
 * FILE:	or_common.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_common.h"
#include "or_mem_util.h"
#include "or_log.h"
#include "or_security_module.h"

/*-----------------------------Local Macro Defn----------------------------*/
#define OR_ALLOC_PKT(pkt) \
do {\
    pkt = (OrUint8 *) or_mem_alloc(OR_PKT_LEN); \
}while(0)

#define BUFFLEN 2048

/*----------------------------Local Variables------------------------------*/
/* Save statically generated DH key pair so that when the public key is
 * read from ORCS or a config file it can be verified from here. Also,
 * when a public key matches the corresponding device will retrieve its
 * key pair from this table */
static OrKeyPairTable keyPairRecord[OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1] = {
    {3000, 
     "04010a0104140a0a0a14040a140a040a0a040a0a140a0201050a0a041401010a",
     "0400030004050303030504030503040303040303050302000103030405000003"
     },
    {3001, 
     "0a0a0a0404140a140a020a0a040414040a140a04040a1414040a0a04040a040a",
     "0303030404050305030203030404050403050304040305050403030404030403"
     },
    {3002, 
     "14020204050a040a0a0204140a0a0a0a0a0a0a050a140a04040a0a0405040a0a",
     "0502020401030403030204050303030303030301030503040403030401040303"
     },
    {3003, 
     "140a0a04010a0a0a0a0a0a0a0a0a010a1404050a040a050a1402050a04141414",
     "0503030400030303030303030303000305040103040301030502010304050505"
     },
};
static OrInt maxfd = -1;
static fd_set rset, wset;
/*------------------------------Local Fn Decln-----------------------------*/
static OrBool or_get_nbr_keypair(OrNeighbor *orNbr, OrKeyPair *nbrKeyPair);


/*------------------------------Local Fn Defn------------------------------*/

/*
 * or_get_nbr_key_pair:
 *
 * retrieve key pair from static table for 'orNbr'
 *
 * returns result as boolean and 'nbrKeyPair' 
 */
static OrBool or_get_nbr_keypair(OrNeighbor *orNbr, OrKeyPair *nbrKeyPair)
{
    OrUint8 savedPubliicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1] = {0};
    OrUint8 savedPrivateKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1] = {0};
    OrUint8 i = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    while(i < (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        if(orNbr->port == keyPairRecord[i].port)
        {
            break;
        }
        i++;
    }

    if(i != (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        or_mem_copy(savedPubliicKey, keyPairRecord[i].publishedPublicKey,
                                             sizeof(keyPairRecord[i].publishedPublicKey));
        or_mem_copy(savedPrivateKey, keyPairRecord[i].recordPrivateKey,
                                             sizeof(keyPairRecord[i].recordPrivateKey));
    }
    else
    {
        goto OUT;
    }

    if(!or_pack_hash_string(savedPubliicKey,
                                    nbrKeyPair->publicKey))
    {
        goto OUT;
    }

    if(!or_pack_hash_string(savedPrivateKey,
                                    nbrKeyPair->privateKey))
    {
        goto OUT;
    }

    result = TRUE;

OUT:
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                    __FUNCTION__, __LINE__, result);
    return result;
}


/*------------------------------Global Fn Defn------------------------------*/

/*
 * or_get_saved_public_private_key:
 *
 * get the public private-key pair for local device from static table by
 * comparing the port number.
 *
 * returns result as boolean
 */
OrBool or_get_saved_public_private_key()
{
    OrUint8 i = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %d %d", __FUNCTION__, __LINE__, 
                                                        orContext.role, 
                                                        orContext.port);

    while(i < orContext.neigborTable.noOfEntriesInNeighborTable)
    {
        if(orContext.port == orContext.neigborTable.orNeighbor[i].port)
        {
            break;
        }
        i++;
    }

    if(i != orContext.neigborTable.noOfEntriesInNeighborTable)
    {
        if(or_get_nbr_keypair(&orContext.neigborTable.orNeighbor[i],
                                            &orContext.keyPair)){
            result = TRUE;
        }
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                    __FUNCTION__, __LINE__, result);

    return result;
}

/*
 * or_validate_public_key_from_neighbor_table:
 *
 * validate that the key provided by ORCS or the key read from config
 * file matches the saved key.
 *
 * returns result as boolean
 */
OrBool or_validate_public_key_from_neighbor_table()
{
    OrUint8 expandedLocalPublicKey[2*OR_PUBLIC_PRIVATE_KEY_LENGTH + 1] = {0};
    OrUint8 i = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    while(i < orContext.neigborTable.noOfEntriesInNeighborTable)
    {
        if(orContext.port == orContext.neigborTable.orNeighbor[i].port)
        {
            break;
        }
        i++;
    }

    if(i != (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        or_unpack_hash_string(orContext.keyPair.publicKey, 
                                            expandedLocalPublicKey);
        if(or_mem_cmp(expandedLocalPublicKey,
             orContext.neigborTable.orNeighbor[i].publishedPublicKey,
                        sizeof(orContext.neigborTable.orNeighbor[i].publishedPublicKey)))
        {
            goto OUT;
        }
    }
    else
    {
        goto OUT;
    }

    result = TRUE;

OUT:
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Validation %s", 
                    __FUNCTION__, __LINE__, result ? "Passed" : "Failed");
    return result;
}

/*
 * or_validate_role_from_neighbor_table:
 *
 * validate that the role in which the device has boot up or
 * initialized is actually the role the ORCS has in its data
 * base for this device or the the role must match with the
 * role read from the config file
 *
 * returns result as boolean
 */
OrBool or_validate_role_from_neighbor_table()
{
    OrUint8 i = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    while(i < orContext.neigborTable.noOfEntriesInNeighborTable)
    {
        if(orContext.port == orContext.neigborTable.orNeighbor[i].port)
        {
            break;
        }
        i++;
    }

    if(i != (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        /* if the local role is sender or receiver then the entry found in 
           neighbor table must be of type end_device */
        if(orContext.role == OR_SENDER || orContext.role == OR_RECEIVER)
        {
            if(orContext.neigborTable.orNeighbor[i].deviceType != OR_END_DEVICE_T)
            {
                goto OUT;
            }
        }
        else if(orContext.role == OR_ROUTER)
        {
            if(orContext.neigborTable.orNeighbor[i].deviceType != OR_ROUTER_T)
            {
                goto OUT;
            }
        }
        else
        {
            goto OUT;
        }
    }
    else
    {
        goto OUT;
    }

    result = TRUE;

OUT:
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Validation %s", 
                    __FUNCTION__, __LINE__, result ? "Passed" : "Failed");
    return result;
}

/*
 * or_get_member_id_from__neighbor_table:
 *
 * member id is typically assigned by the ORCS or it
 * has to be read from a config file. This fn reads
 * it from the neighbor table which is formed by the
 * data provided by the ORCS or from the data read from
 * the config file.
 *
 * returns result as boolean
 */
OrBool or_get_member_id_from__neighbor_table()
{
    OrUint8 i = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    while(i < (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        if(orContext.port == orContext.neigborTable.orNeighbor[i].port)
        {
            break;
        }
        i++;
    }

    if(i != (OR_CONFIG_MAX_NO_OF_NEIGHBOR + 1))
    {
        orContext.memberId = orContext.neigborTable.orNeighbor[i].memberId;
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Assigned member id is %d", 
                                    __FUNCTION__, __LINE__, orContext.memberId);
    }
    else
    {
        goto OUT;
    }

    result = TRUE;

OUT:
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);
    return result;
}


/*
 * or_get_neighbor_dh_keys:
 *
 * dh keys for each of the neighbor
 * result will be saved in orContext.neigborTable
 *
 * returns result as boolean
 */
OrBool or_get_neighbor_dh_keys()
{
    OrUint8 itr = 0;
    OrNeighborTable *nbrTable = &orContext.neigborTable;
    OrBool result = TRUE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

#ifndef OR_DISABLE_LINK_ENCRYPTION
    for(; itr < nbrTable->noOfEntriesInNeighborTable; itr++) {
        OrKeyPair nbrKeyPair;

        if(nbrTable->orNeighbor[itr].memberId != orContext.memberId) {
            if(or_get_nbr_keypair(&nbrTable->orNeighbor[itr], &nbrKeyPair)){
                or_produce_secret(&orContext.keyPair, &nbrKeyPair, 
                                    nbrTable->orNeighbor[itr].orDhSecret);
            }
            else {
                result = FALSE;
                break;
            }
        }
        else {
            or_mem_set(nbrTable->orNeighbor[itr].orDhSecret,
                                        0xff, OR_DH_SECRET_LENGTH);
        }
    }
#endif

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

/*
 * or_get_self_dh_key:
 *
 * create an or pkt of the standard or format
 *
 * returns result as boolean
 */
OrBool or_get_self_dh_key()
{
    OrUint8 k = 0;
    OrBool result = FALSE;
#if 0
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    for(; k < orContext.neigborTable.noOfEntriesInNeighborTable; k++) {
        if(orContext.memberId == orContext.neigborTable.orNeighbor[k].memberId) {
            or_mem_copy(orContext.orDhSecret, 
              orContext.neigborTable.orNeighbor[k].orDhSecret, OR_DH_SECRET_LENGTH);
            result = TRUE;
            break;
        }
    }
#endif
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

/*
 * or_create_or_pkt:
 *
 * create an or pkt of the standard or format
 *
 * returns result as boolean
 */
OrBool or_create_or_pkt(OrUint8 *linkKey,
                        OrUint32 cid,
                        OrUint8 cmd,
                        OrUint8 type,
                        OrUint8 *data,
                        OrUint16 dataLength,
                        OrUint8 mac[OR_MAC_FLD_LEN],
                        OrUint8 **orPkt)
{
    OrBool result = FALSE;
    OrUint8  *pkt = NULL;
    OrUint8  *frame = NULL;
    OrUint8 toremove = 0, *toremove1 = NULL;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    /* Form an OR packet of the following format 
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    +  challenge(9)  +  cid(4)  +  cmd(1)  +  type(1)  +  len(2)+     payload(760)     +  ac(8)  +
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    */

    if(data != NULL) {
        if(dataLength <= OR_MSS) {

            /* allocate pkt and initialize */
            OR_ALLOC_PKT(pkt);
            or_mem_zero(pkt, OR_PKT_LEN);

            frame = pkt;

            or_mem_copy(frame, OR_CHALLENGE_TEXT, OR_CHALLENGE_LEN);
            or_crypt_challenge(frame, linkKey);
            frame += OR_CHALLENGE_LEN;

            if(pkt != NULL) {
                /* pack cid field */
                OR_COPY_UINT32_TO_LITTLE_ENDIAN(cid, frame);
                frame += OR_CID_FLD_LEN;
                /* pack cmd filed */
                OR_COPY_UINT8_TO_LITTLE_ENDIAN(cmd, frame);
                frame += OR_CMD_FLD_LEN;
                /* pack type field */
                OR_COPY_UINT8_TO_LITTLE_ENDIAN(type, frame);
                frame += OR_TYPE_FLD_LEN;
                /* pack payload length field */
                OR_COPY_UINT16_TO_LITTLE_ENDIAN(dataLength, frame);
                frame += OR_PAYLD_LEN_FLD_LEN;
                printf("header bfr encryption\n");
                toremove1 = pkt + OR_CHALLENGE_LEN;
                for(toremove = 0; toremove < OR_PKT_HDR_LEN; toremove++) {
                    printf("%x ", toremove1[toremove]);
                }
                printf("\n");
                /* encrypt header using dh secret */
                or_encrypt_hdr(pkt + OR_CHALLENGE_LEN, linkKey);
                printf("header after encryption\n");
                toremove1 = pkt + OR_CHALLENGE_LEN;
                for(toremove = 0; toremove < OR_PKT_HDR_LEN; toremove++) {
                    printf("%x ", toremove1[toremove]);
                }
                printf("\n");
                /* pack payload*/
                or_mem_copy(frame, data, dataLength);
                frame += dataLength;
                if(dataLength < OR_PAYLD_FLD_LEN) {
                    /* padding required */
                    or_mem_set(frame, OR_PAD_BYTE, (OR_PAYLD_FLD_LEN - dataLength));
                    frame += (OR_PAYLD_FLD_LEN - dataLength);
                }
                /* pack mac field*/
                or_mem_copy(frame, mac, OR_MAC_FLD_LEN);
                frame += OR_MAC_FLD_LEN;

                /* return orPkt */
                *orPkt = pkt;
                result = TRUE;
            }
            else {
                OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Pkt allocation failed",
                                            __FUNCTION__, __LINE__);
            }
        }
        else {
             OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Payload bigger than "
                                        "allowed. Max allowed (%d) bytes",
                                        __FUNCTION__, __LINE__, OR_MSS);
        }
    }
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> error> data = NULL", __FUNCTION__, __LINE__);
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                __FUNCTION__, __LINE__, result);

    return result;
}

/*
 * or_parse_incoming_data:
 *
 * parse incoming data and copy relevalt info to a structure 
 * of format OrIncmingDataTuple. Refer to or_types.h for the
 * format of this structure
 *
 * returns nothing 
 */
OrBool or_parse_incoming_data(const OrUint8 *data,
                            OrUint16 dataL,
                            OrIncmingDataTuple *iTuple) 
{
    OrUint32 cid;
    OrCmd    cmd;
    OrPayloadType type;
    OrUint8 mac[OR_MAC_FLD_LEN];
    OrUint8 hdr[OR_PKT_HDR_LEN];
    const OrUint8 *pdata  = NULL;
    OrUint8 *pload  = NULL;
    OrUint16 ploadL = 0;
    OrUint8 chlngBuf[OR_CHALLENGE_LEN] = {0}, k = 0;
    OrNeighborTable *nbrTble = &orContext.neigborTable;
    OrBool result = FALSE;
    OrUint8 toremove = 0;
    const OrUint8 *toremove1 = NULL;

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> %p %u>>",
                                    __FUNCTION__, __LINE__,
                                    data, dataL);

    OR_ASSERT(((data == NULL) || (dataL != OR_PKT_LEN)),"Invalid incoming data\n");

    /* Form an OR packet of the following format 
    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    +  cid(4)  +  cmd(1)  +  type(1)  +  len(2)+     payload(760)     +   ac(8)   +
    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    */

    or_mem_set(iTuple->linkKey, 0x00, OR_DH_SECRET_LENGTH);
    for(k = 0; k < nbrTble->noOfEntriesInNeighborTable; k++) {
        or_mem_copy((void *)chlngBuf, (void *)data, OR_CHALLENGE_LEN);
        or_crypt_challenge(chlngBuf, nbrTble->orNeighbor[k].orDhSecret);
        if(!strncmp(chlngBuf, OR_CHALLENGE_TEXT, OR_CHALLENGE_LEN)) {
            or_mem_copy(iTuple->linkKey,
                nbrTble->orNeighbor[k].orDhSecret, OR_DH_SECRET_LENGTH);
            result = TRUE;
            break;
        }
    }

    if(result == TRUE) {
        toremove1 = data + OR_CHALLENGE_LEN;
        /* decrypt header(8) using DH secret */
        printf("Header before decryption\n");
        for(toremove = 0; toremove < OR_PKT_HDR_LEN; toremove++) {
            printf("%x ", toremove1[toremove]);
        }
        printf("\n");

        or_decrypt_hdr(data + OR_CHALLENGE_LEN,
                        dataL - OR_CHALLENGE_LEN, hdr, iTuple->linkKey);

        printf("Header after decryption\n");
        for(toremove = 0; toremove < OR_PKT_HDR_LEN; toremove++) {
            printf("%x ", hdr[toremove]);
        }
        printf("\n");

        pdata = data + OR_CHALLENGE_LEN;

        cid = OR_GET_UINT32_FROM_LITTLE_ENDIAN(hdr);
        pdata += OR_CID_FLD_LEN;
        cmd = (OrCmd)hdr[OR_CID_FLD_LEN];
        pdata += OR_CMD_FLD_LEN;
        type   = hdr[OR_CID_FLD_LEN + OR_CMD_FLD_LEN];
        pdata += OR_TYPE_FLD_LEN;
        ploadL = OR_GET_UINT16_FROM_LITTLE_ENDIAN
                    (hdr + OR_CID_FLD_LEN + OR_CMD_FLD_LEN + OR_TYPE_FLD_LEN);
        pdata += OR_PAYLD_LEN_FLD_LEN;
        /* No need to advance hdr any more. */
        pload = (OrUint8 *) or_mem_alloc(ploadL);

        OR_ASSERT((pload == NULL), "or_parse_incoming_data> mem alloc failed\n");

        or_mem_copy((void *)pload, (void *)pdata, ploadL);

        pdata += OR_PAYLD_FLD_LEN;

        or_mem_copy((void *)mac, (void *)pdata, OR_MAC_FLD_LEN);

        OR_ASSERT((iTuple == NULL), "or_parse_incoming_data> iTuple == NULL\n");

        iTuple->cid    = cid;
        iTuple->cmd    = cmd;
        iTuple->pLoadT = type;
        iTuple->pLoad  = pload;
        iTuple->pLoadL = ploadL;
        or_mem_copy(iTuple->mac, mac, OR_MAC_FLD_LEN);
    }
    else {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> >>"
                                   "Challenge failed!!!", __FUNCTION__, __LINE__);
    }

    OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> %u %u <<",
                                __FUNCTION__, __LINE__, result, iTuple->pLoadL);

    return result;
}

/*
 * or_connect_to_remote_server:
 *
 * connect to remote server and return an fd
 *
 * returns result as boolean and an fd 
 */

OrInt8 or_connect_to_remote_server(OrInt *clientFd,
                                OrCharString *host,
                                OrUint16 port,
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

#if 0
    flags = fcntl(cFd, F_GETFL, 0);
    OR_ASSERT((flags == -1), "fctrl failed\n");
    fcntl(cFd, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(cFd, F_GETFL, 0);

    OR_ASSERT(((flags & O_NONBLOCK) != O_NONBLOCK), "socket not non-blocking\n");
#endif

    /* Initialize socket address */
    or_mem_zero(&server, sizeof(struct sockaddr_in));

    server.sin_family      = AF_INET;
    server.sin_port        = htons(port);

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

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Connecting to: %d.%d.%d.%d "
                               "port: %d",
                             __FUNCTION__, __LINE__,
                            (OrInt)(server.sin_addr.s_addr & 0xFF),
                            (OrInt)((server.sin_addr.s_addr & 0xFF00)>>8),
                            (OrInt)((server.sin_addr.s_addr & 0xFF0000)>>16),
                            (OrInt)((server.sin_addr.s_addr & 0xFF000000)>>24),
                            port);


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

OUT:
    *clientFd = cFd;
    result    = cFd;
    return result;
}

/*
 * or_is_replayed_onion:
 *
 * check whether an onion has been replayed or not 
 * by checking its presence in expd and unexpd lists
 *
 * returns result as boolean 
 */
OrBool or_is_replayed_onion(OrIncmingDataTuple *iTuple,
                            OrOnionList *unExpdOnionListH,
                            OrOnionList *expdOnionListH,
                            OrMutexHandle unExpdOnionListLock,
                            OrMutexHandle expdOnionListLock)
{
    OrOnionListNode *node = unExpdOnionListH;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> >>", __FUNCTION__, __LINE__);

    or_mutex_lock(unExpdOnionListLock);
    or_mutex_lock(expdOnionListLock);

    while(node != NULL){
        if((node->onion.orLen == iTuple->pLoadL)
           && !(or_mem_cmp(node->onion.orOnion, iTuple->pLoad, iTuple->pLoadL))) {
           break;
        }
        node = node->next;
    }

    if(node != NULL) {
        result = TRUE;
    }
    else {
        node = expdOnionListH;
        while(node != NULL){
            if((node->onion.orLen == iTuple->pLoadL)
               && !(or_mem_cmp(node->onion.orOnion, iTuple->pLoad, iTuple->pLoadL))) {
               break;
            }
            node = node->next;
        }
        if(node != NULL) {
            result = TRUE;
        }
    }

    or_mutex_unlock(unExpdOnionListLock);
    or_mutex_unlock(expdOnionListLock);

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> %u <<", 
                                    __FUNCTION__, __LINE__, result);

    return result;
}

