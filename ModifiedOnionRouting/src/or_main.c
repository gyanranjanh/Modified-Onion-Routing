/*
 * FILE:	or_main.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */
#include "or_types.h"
#include "or_log.h"
#include "or_common.h"
#include "or_mem_util.h"
#include "or_security_module.h"
#include "or_sender.h"
#ifndef ORCS_NOT_READY
#include "or_orcs_helper.h"
#endif

#define BASE_IP "127.0.0.1"
#define or_insert_line_to_list(x, y, z, line, read) \
do { \
    x = (struct templines *) or_mem_alloc(sizeof(struct templines)); \
    x->line = (OrCharString *) or_mem_alloc(read); \
    or_mem_zero(x->line, read); \
    or_mem_copy(x->line, line, read); \
    x->next = NULL; \
    if(z == NULL) \
    { \
        z = x; \
    }\
    else \
    { \
        y = z; \
        while(y->next != NULL) {y = y->next;} \
        y->next = x; \
    } \
}while(0)

#define or_free_line_list(templine, tempt) \
do { \
    tempt = templine; \
    while(tempt->next != NULL) \
    { \
        templine = tempt; \
        tempt = tempt->next; \
        or_mem_free(templine->line); \
        or_mem_free(templine); \
    } \
    or_mem_free(tempt->line); \
    or_mem_free(tempt); \
} while(0)


/*------------------Global Variable---------------------*/
OrContext orContext = {0};

/*------------------Static Variable---------------------*/
#if 0
OrNeighborTable orStaticNeighborTable[] =
{
    {0, OR_ROUTER_T, OR_BASE_TCP_SERVER_PORT + 1, BASE_IP, 0},
    {0, OR_ROUTER_T, OR_BASE_TCP_SERVER_PORT + 2, BASE_IP, 0},
    {0, OR_ROUTER_T, OR_BASE_TCP_SERVER_PORT + 3, BASE_IP, 0},
};
#endif
OrNeighborTable orStaticNeighborTable;


/*----------------Static Function Declaration-----------*/
static void or_init(OrRole role, OrUint16 port);
static OrInt or_server_init(void);
static void usage(const OrCharString *argv[]);
static void or_find_role_in_arguments(OrInt8 argc, 
                                                   const OrCharString *argv[],
                                                   OrRole *role);
static void or_find_port_in_arguments(OrInt8 argc, 
                                                   const OrCharString *argv[],
                                                   OrUint16 *port);
#ifdef ENABLE_OR_LOG
static OrCharString* or_find_logfile_path_in_arguments(OrInt8 argc, 
                                                               const OrCharString *argv[]);
#endif
#ifdef ORCS_NOT_READY
static OrCharString* or_find_nwkLayout_file_path_in_arguments(OrInt8 argc, 
                                                               const OrCharString 
                                                               *argv[]);
#endif
static void or_validate_in_arguments(OrInt8 argc, 
                                                 const OrCharString *argv[],
                                                 OrRole *role,
                                                 OrUint16 *port,
                                                 OrCharString **logFile
#ifdef ORCS_NOT_READY
                                                 ,OrCharString **nwkLayoutFile
#endif
                                                 );



/*----------------Static Function Defn------------------*/
static void or_init(OrRole role, OrUint16 port)
{
    or_mem_zero(&orContext, sizeof(OrContext));
    orContext.role = role;
    orContext.port = port;
    or_mem_copy(&orContext.neigborTable, &orStaticNeighborTable, \
                                            sizeof(OrNeighborTable));
}
static OrInt or_server_init()
{
    OrInt result;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* Create server socket thread */
    result = or_create_socket_thread();
    /* Wait here for now so that the process doesn't die */
    while(1);
    
    if(result != 0)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Failed to create"
                    "or_listen_socket_thread!!!!", __FUNCTION__, __LINE__);
    }

    return result;
}

static void usage(const OrCharString *argv[])
{
#ifndef ENABLE_OR_LOG
    fprintf(stderr, "usage: %s <role optionally port>\n", argv[0]);
#else
    fprintf(stderr, "usage: %s <role optionally port logfile>\n", argv[0]);
#endif
    fprintf(stderr, "role: [sender, router, receiver]\n");
}

static void or_find_role_in_arguments(OrInt8 argc, 
                                                   const OrCharString *argv[],
                                                   OrRole *role)
{
    OrCharString *findString = NULL;
    OrUint8 count;

    for(count=0; count < argc; count++)
    {
        findString = strstr(argv[count], "role");
        if(findString != NULL)
        {
            break;
        }
    }

    if(findString == NULL)
    {
        /* role not found. exit. */
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }
    else
    {
        findString = strstr(findString, "=");
    }

    if(findString == NULL)
    {
        /* role not found. exit. */
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }
    else
    {
        findString++;
    }

    if (strcmp("sender", findString) == 0)
    {
        *role = OR_SENDER;
    }
    else if (strcmp("receiver", findString) == 0)
    {
        *role = OR_RECEIVER;
    }
    else if (strcmp("router", findString) == 0)
    {
        *role = OR_ROUTER;
    }
    else
    {
        fprintf(stderr, "error! Undefined role\n");
        exit(1);
    }

    fprintf(stdout, "role is: %d\n", *role);
}

static void or_find_port_in_arguments(OrInt8 argc, 
                                                   const OrCharString *argv[],
                                                   OrUint16 *port)
{
    OrCharString *findString = NULL;
    OrUint8 count;

    *port = 0xFFFF;

    for(count=0; count < argc; count++)
    {
        findString = strstr(argv[count], "port");
        if(findString != NULL)
        {
            break;
        }
    }

    if(findString == NULL)
    {
        /* port not found. exit. */
        goto OUT;
    }
    else
    {
        findString = strstr(findString, "=");
    }

    if(findString == NULL)
    {
        /* port not found. exit. */
        goto OUT;
    }
    else
    {
        findString++;
    }

    *port = atoi(findString);

OUT:
    fprintf(stdout, "port is: %d\n", *port);
    return;
}

#ifdef ENABLE_OR_LOG
static OrCharString* or_find_logfile_path_in_arguments(OrInt8 argc, 
                                                               const OrCharString *argv[])
{
    OrCharString *findString = NULL;
    OrUint8 count;

    for(count=0; count < argc; count++)
    {
        findString = strstr(argv[count], "logfile");
        if(findString != NULL)
        {
            break;
        }
    }

    if(findString == NULL)
    {
        /* logfile path not found. exit. */
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }
    else
    {
        findString = strstr(findString, "=");
    }

    if(findString == NULL)
    {
        /* logfile path not found. exit. */
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }
    else
    {
        findString++;
        /* Trim leading space */
        while(isspace(*findString)) findString++;
        if(*findString == 0)
        {
            /* logfile not found. exit. */
            fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
            usage(argv);
            exit(1);
        }
    }

OUT:
    fprintf(stdout, "lofgile path is: %s\n", findString);
    return findString;
}
#endif

#ifdef ORCS_NOT_READY
static OrCharString* or_find_nwkLayout_file_path_in_arguments(OrInt8 argc, 
                                                               const OrCharString *argv[])
{
    OrCharString *findString = NULL;
    OrUint8 count;

    for(count=0; count < argc; count++)
    {
        findString = strstr(argv[count], "nwkLayoutFile");
        if(findString != NULL)
        {
            break;
        }
    }

    if(findString == NULL)
    {
        /* Layout file path not found.*/
        fprintf(stderr, "<%s Line%d> Network Layout File not found\n", __FUNCTION__, __LINE__);
        goto OUT;
    }
    else
    {
        findString = strstr(findString, "=");
    }

    if(findString == NULL)
    {
        /* Layout file path not found. */
        fprintf(stderr, "<%s Line%d> Network Layout File not found\n", __FUNCTION__, __LINE__);
        goto OUT;
    }
    else
    {
        findString++;
        /* Trim leading space */
        while(isspace(*findString)) findString++;
        if(*findString == 0)
        {
            /* Layout file path not found. */
            fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
            goto OUT;
        }
    }

OUT:
    if((findString != NULL) || (*findString != 0))
    {
        fprintf(stdout, "Network layout file path is: %s\n", findString);
    }
    else if(*findString != 0)
    {
        findString = NULL;
    }

    return findString;
}

void * or_retrieve_field_values(const OrCharString *findString,
                                            const OrCharString *findSubString)
{
    OrCharString *target = NULL, *end = NULL;;


    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* Skip the leading spaces */
    while(isspace(*findString) && (findString != findSubString)) findString++;

    if(findString == findSubString)
    {
        OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> required entry missing", __FUNCTION__, __LINE__);
        goto OUT;
    }
    else
    {
        /* Retrieve member id value */
        target = (OrCharString *) or_mem_alloc(findSubString - findString);
        or_mem_zero(target, (findSubString - findString));
        or_mem_copy((void *)target, (void *)findString, (findSubString - findString));
        end = target + (findSubString - findString) - 1;
        end--;
        while(end != target && isspace(*end))
        {
            end--;
        }
        if(isspace(*(end + 1)))
        {
            *(end + 1) = '\0';
        }
    }

OUT:
    return target;
}

static OrBool or_parse_read_lines(const OrCharString **lines, OrUint8 noLines)
{
    const OrCharString *findString = NULL, *findSubString = NULL;
    char      *target = NULL;
    OrUint8 i = 0, count = 0;
    OrBool result = FALSE;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    /* Need to find 'Member Id', 'Device Type', 'IP', 'Port' & 'Public Key' */

    for(count = 0; count < noLines; count++)
    {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> %d : %s", 
                                             __FUNCTION__, __LINE__,
                                             count, lines[count]);
    }

    if(!strstr(lines[0], "Member Id")
        || !strstr(lines[0], "Device Type")
        || !strstr(lines[0], "IP")
        || !strstr(lines[0], "Port")
        || !strstr(lines[0], "Public Key"))
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> required field missing", __FUNCTION__, __LINE__);
        goto OUT;
    }

    for(i = 1; i < noLines; i++)
    {
        findString = findSubString = lines[i];
        count = 0;

        while(count < 5)
        {
            findString = findSubString;
            if(((findSubString = strstr(findString, "||")) == NULL)
                && (*findString == 0))
            {
                OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> required '||'  or"
                                           "field missing", __FUNCTION__, __LINE__);
                goto OUT;
            }
            else
            {
                if(findSubString == NULL)
                {
                    findSubString = findString + strlen(findString);
                }

                target = or_retrieve_field_values(findString, findSubString);

                if(target == NULL)
                {
                    goto OUT;
                }
                else
                {
                    switch(count)
                    {
                        case 0:
                        {
                            orStaticNeighborTable.orNeighbor[i - 1].memberId = atoi(target);
                            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> target : %s memberId : %d",
                                                    __FUNCTION__, __LINE__,
                                               target, orStaticNeighborTable.orNeighbor[i - 1].memberId);
                        }
                        break;
                        case 1:
                        {
                            if(!strcmp(target, "OR_ROUTER"))
                            {
                                orStaticNeighborTable.orNeighbor[i - 1].deviceType = OR_ROUTER_T;
                            }
                            else if(!strcmp(target, "OR_END_DEVICE"))
                            {
                                orStaticNeighborTable.orNeighbor[i - 1].deviceType = OR_END_DEVICE_T;
                            }
                            else
                            {
                                OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> Device"
                                                            "Type not supported %s>",
                                                            __FUNCTION__, __LINE__, 
                                                            target);
                                goto OUT;
                            }
                            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> target : %s deviceType : %d", 
                                                    __FUNCTION__, __LINE__, 
                                          target, orStaticNeighborTable.orNeighbor[i - 1].deviceType);
                        }
                        break;
                        case 2:
                        {
                            or_mem_copy(orStaticNeighborTable.orNeighbor[i - 1].ip, target, strlen(target));
                            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> target : %s ip : %s",
                                                        __FUNCTION__, __LINE__, 
                                                     target, 
                                                     orStaticNeighborTable.orNeighbor[i - 1].ip);
                        }
                        break;
                        case 3:
                        {
                            orStaticNeighborTable.orNeighbor[i - 1].port= atoi(target);
                            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> target : %s port: %d", 
                                                        __FUNCTION__, __LINE__,
                                                  target, orStaticNeighborTable.orNeighbor[i - 1].port);
                        }
                        break;
                        case 4:
                        {
                            or_mem_zero(orStaticNeighborTable.orNeighbor[i - 1].publishedPublicKey, 
                                                                      OR_PUBLIC_PRIVATE_KEY_LENGTH);
                            or_mem_copy(orStaticNeighborTable.orNeighbor[i - 1].publishedPublicKey,
                                                                    target, strlen(target));
                            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> target : %s publicKey : %s", 
                                            __FUNCTION__, __LINE__,
                                            target, orStaticNeighborTable.orNeighbor[i - 1].publishedPublicKey);
                        }
                        break;
                        default:
                        {
                            OR_LOG(OR_LOG_LEVEL_ERROR,"<%s (Line: %d)> required"
                                                      "Fatal error during parsing",
                                                      __FUNCTION__, __LINE__);
                            goto OUT;
                        }
                    }

                    or_mem_free(target);
                    /* skip the delimeters */
                    findSubString += 2;
                    /* Increament the no of delimeters encouneted so far. Total 
                     * should be 5 */
                    count++;
                }
            }
        }
        orStaticNeighborTable.noOfEntriesInNeighborTable++;
    }
OUT:
    if(count == 5)
    {
        /* This check may be needed to be refined later */
        result = TRUE;
    }
    return result;
}

static OrBool or_parse_nwk_layout_file(const OrCharString *nwkLayoutFile)
{
    OrFile *fp = NULL;
    OrCharString *line = NULL;
    OrCharString **lines = NULL;
    OrSize len = 0;
    OrSsize read;
    OrUint8 i = 0, noOfLines = 0;
    OrBool result = FALSE;
    struct templines{OrCharString *line; struct templines *next;};
    struct templines *templine = NULL, *temp = NULL, *tempt = NULL;

    fp = fopen(nwkLayoutFile, "r");

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d) %s>", __FUNCTION__, __LINE__, nwkLayoutFile);


    if(fp == NULL)
    {
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> Invalid 'nwkLayoutFile' file. Can't open", 
                                                                    __FUNCTION__, __LINE__);
        goto OUT;
    }

    while ((read = getline(&line, &len, fp)) != -1)
    {
#if 0
        printf("Retrieved line of length %zu :\n", read);
        printf("%s\n", line);
#endif
        or_insert_line_to_list(temp, tempt, templine, line, read);
        noOfLines++;
    }

    if(noOfLines == 0)
    {
        goto OUT;
    }

    lines = (OrCharString **) or_mem_alloc(sizeof(OrCharString *) * noOfLines);

    tempt = templine;
    while(tempt != NULL)
    {
        lines[i++] = tempt->line;
        tempt = tempt->next;
    }

    result = or_parse_read_lines((const OrCharString **)lines, noOfLines);

OUT:
    if(templine != NULL)
    {
        or_free_line_list(templine, tempt);
        templine = temp = tempt = NULL;
    }
    if(lines != NULL)
    {
        or_mem_free(lines);
    }
    if(line != NULL)
    {
        or_mem_free(line);
    }
    if(fp != NULL)
    {
        fclose(fp);
    }
    return result;
}
#endif


static void or_validate_in_arguments(OrInt8 argc, 
                                                 const OrCharString *argv[],
                                                 OrRole *role,
                                                 OrUint16 *port,
                                                 OrCharString **logFile
#ifdef ORCS_NOT_READY
                                                 ,OrCharString **nwkLayoutFile
#endif
                                                 )
{
    if(argc < 2) 
    {
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }

    fprintf(stdout, "argv[1]: %s\n", argv[1]);

    /* find role in arguments */
    or_find_role_in_arguments(argc, argv, role);

    /* find port in arguments */
    or_find_port_in_arguments(argc, argv, port);

#ifdef ENABLE_OR_LOG
    if(argc < 3) 
    {
        fprintf(stderr, "<%s Line%d>\n", __FUNCTION__, __LINE__);
        usage(argv);
        exit(1);
    }

    /* find lig file path */
    *logFile = or_find_logfile_path_in_arguments(argc, argv);

#endif

#ifdef ORCS_NOT_READY
#ifdef ENABLE_OR_LOG
    if(argc >= 4)
#else
    if(argc >= 3)
#endif
    {
        /* Look for neighbor table layout */
        *nwkLayoutFile = or_find_nwkLayout_file_path_in_arguments(argc, argv);
    }
#endif
}

void main(OrInt8 argc, OrCharString *argv[])
{
    OrRole role  = OR_INVALID;
    OrInt result = 0, clientFd[2];
    OrUint16 port = OR_BASE_TCP_SERVER_PORT;
    OrCharString *logFile = NULL;
#ifdef ORCS_NOT_READY
    OrUint8 i = 0;
    OrCharString *nwkLayoutFile = NULL;
#endif

    /* validate the input arguments */
#ifndef ORCS_NOT_READY
    or_validate_in_arguments(argc, (const OrCharString **)argv, &role, &port, &logFile);
#else
    or_validate_in_arguments(argc, (const OrCharString **)argv, &role, &port, \
                                                              &logFile, &nwkLayoutFile);
#endif

    /* Initialize context */
    or_init(role, port);

    /* Initialize log module */
    or_log_init(logFile);

    /* Initialize security module */
    or_init_security();

    /* initialize timer module */
    or_timer_module_init();

    /* Create Mutex */
    if(!or_mutex_create(&orContext.orLock))
    {
        OR_LOG(OR_LOG_LEVEL_ERROR, "<%s (Line: %d)> Mutex create failed",
                                                    __FUNCTION__, __LINE__);
        goto OUT;
    }

    OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> OR Role = %d port = %d",
                                        __FUNCTION__, __LINE__,
                                        orContext.role, orContext.port);


#ifdef OR_KEY_TEST
    or_key_test();
#endif

#ifndef ORCS_NOT_READY
    /* Generate public/private key pair */
    or_get_key_pair();
    /* At this point we are supposed to connect to ORCS and create account
     * and thus establish a secure session with it using symmetric key.
     * After that we provide ORCS with our public key it will create an
     * entry in its data base assigning a member id. Other fields of the
     * entry will be IP, port, device type, public key and the symmetric 
     * key itself. After that ORCS will pass the table to us and update the
     * entry to existing members */
    if(or_establish_orcs_session() == FALSE)
    {
        goto OUT;
    }
#else
    /* Otherwise read neighbor table from file */
    /* Read network layout configuration file */
    if(nwkLayoutFile == NULL)
    {
        /* network layout configuration file not found */
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Network layout "
                                   "configuration file not found. exiting...",
                                        __FUNCTION__, __LINE__);
        goto OUT;
    }
    else
    {
        if(!or_parse_nwk_layout_file(nwkLayoutFile))
        {
            /* network layout configuration file not found */
            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> Network layout"
                                       "configuration file parsing"
                                       "failed. exiting...",
                                            __FUNCTION__, __LINE__);
            goto OUT;
        }
        else
        {
            /* Network Layout File parsed successfully. Proceed. */

            /* Since we do not have a private key (ORCS not ready - so we did 
             * not generate key pair. we must work using pregenrated keys)
             * we must read it from static table. Since port was passed as
             * a program argument we must use port to index into the static
             * table. we take the private key from here and the rest of the
             * details from the 'neigbor table static 
             */

            /* copy network table to orContext */
            or_mem_copy(&orContext.neigborTable, &orStaticNeighborTable, \
                                                    sizeof(OrNeighborTable));
            OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> "
                            "NO of entries in neighbor table %d", 
                            __FUNCTION__, __LINE__, orContext.neigborTable.noOfEntriesInNeighborTable);

            /* get the save public key from static table. 
             * note that we need not do this if the rele-
             * vant info is passed by ORCS */
            if(!or_get_saved_public_private_key()) {
                goto OUT;
            }

            /* validate that the key read from config file or the
             * key provided by ORCS is actually the key this deivce
             * generated */
            if(!or_validate_public_key_from_neighbor_table()) {
                goto OUT;
            }

            /* validate that the role in which the device has boot up
             * or initialized is the role ORCS has for this device or
             * the device role should match with the role read from the
             * config file for this device*/
            if(!or_validate_role_from_neighbor_table()) {
                goto OUT;
            }

            /* Validations passed - get memberid from neighbor table */
            if(!or_get_member_id_from__neighbor_table()) {
                goto OUT;
            }

            /* get dh key for each of the member in the neighbor table
             * as it will be required for link encryption */
            if(!or_get_neighbor_dh_keys()) {
                goto OUT;
            }

#if 0
            /* find self dhsecret and copy it to orContext.dhkey*/
            if(!or_get_self_dh_key()) {
                goto OUT;
            }
#endif
        }
    }
#endif


    switch(role)
    {
        case OR_SENDER:
        {
#ifdef OR_CLIENT_SERVER_TEST
            /* Following is test code only */
            or_run_client_server_test(&clientFd[0], "127.0.0.1", OR_HOST_IP);
            while(1);
#endif

            /* 1. Maintain a static table of neighbor ID, IP, PORT, TYPE, PUBLIC 
             *    KEY.
             * 2. Have a message to send. Initially get from stdip. Later extend to 
             *    read message from file.
             * 3. Create an onion.
             * 4. Calulate MAC. Add MAC to frame.
             * 5. Encrypt data using DH secret.
             * 6. Pass it to the next OR.
             * 7. Wait for reply.
             */

            /* inititialize app proxy */
            or_app_proxy_init();
            or_sender_init();
        }
        break;
        case OR_RECEIVER:
        {
            /* 1. Itz VC routing table doesn't have next hop.It is the end 
             *    point of VC.
             * 3. It may either receive an onion or a message to be routed in an
             *    already formed VC.
             * 4. Recalculate MAC. Validate.
             * 5. Decrypt data using DH shared secret.
             * 6. If it receives an onion (CREATE cmd) then it must create an entry
             *    into its existing VC routing table with ACI, Expiration Time, 
             *    Ff, Kf, Fb, Kb, Src Ip-Port.
             * 7. If it receives a DATA cmd then it already has a VC. Look up 
             *    in the table for corresponding ACI, retreive Ff, Kf, peel 
             *    off the last layer.
             * 8. If required generate reply.
             * 9. Encrypt using DH secret and add MAC.
             *10. Send using the same ACI where the message is received.
             */
             
             /* OR receiver must have a server runnig for accepting connections.
              */
            or_receiver_init();
            if(or_server_init() != 0)
            {
                goto OUT;
            }
            while(1);
        }
        break;
        case OR_ROUTER:
        {
            /* 1. Maintain a static table of neighbor ID, IP, PORT, TYPE, PUBLIC 
             *    KEY.
             * 2. Listens for incoming connections.
             * 3. It may either receive an onion or a message to be routed in an
             *    already formed VC.
             * 4. Recalculate MAC. Validate.
             * 5. Decrypt data using DH shared secret.
             * 6. If it receives an onion (CREATE cmd) then it must create an entry
             *    into its existing VC routing table with ACI, Expiration Time, 
             *    Ff, Kf, Fb, Kb, Src Ip-Port, Next-hop Ip-Port.
             * 7. If it receives a DATA cmd then it already has a VC. Look up 
             *    in the table for corresponding ACI, retreive Ff, Kf, peel 
             *    off a layer add padding.
             * 8. Encrypt using DH shared key and add MAC.
             * 9. Check message type. If delay-tolerant then add it to 
             *    Binomial Mix pool.
             * 10. Send data MIX when generates chance or if delay-intolerant message.
             */

             /* OR must have a server runnig for accepting connections.
             * If router then it must be capable of accepting multiple
             * connections.
             */

            or_router_init();
            if(or_server_init() != 0)
            {
                goto OUT;
            }
            while(1);
        }
        break;
    }

OUT:
    OR_LOG(OR_LOG_LEVEL_CRITICAL, "Final Exit Test");
    or_log_deinit();
    or_app_proxy_deinit();
    or_sender_deinit();
    or_router_deinit();
    or_receiver_deinit();
    or_timer_module_deinit();
    or_mutex_destroy(orContext.orLock);
    return;
}

