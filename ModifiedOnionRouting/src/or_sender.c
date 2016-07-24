/*
 * FILE:	or_sender.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_sender.h"
#include "or_application_proxy.h"
#include "or_common.h"
#include "or_log.h"

#define CLEAN_STRING "\n\n"

/*---------------------------Local Varables and data---------------*/
OrThread orSendAppThd;
OrBool orTerminateSenderProcess = FALSE;
static OrMutexHandle orSendAppDataIndLock = NULL;

/*---------------------------Private Fn Prototype------------------*/
static char *or_getline(void);
static void *or_sender_handler(void *thread_param);
static void or_sender_init_handshake_handler_app_data_ind(void *sessn,
                                           OrUint8 *data, OrUint16 dataL);
static void or_sender_app_data_ind(void *sessn, OrUint8 *data, OrUint16 dataL);
static void or_sender_send_initial_greetings(void);

/*---------------------------Private Fn Defn-----------------------*/

static char * or_getline(void)
{
    char *line = or_mem_alloc(100), *linep = line;
    OrSize lenmax = 100, len = lenmax;
    int c;

    if(line == NULL)
        return NULL;

    while(TRUE) {
        c = fgetc(stdin);
        if(c == EOF) {
            break;
        }

        if(--len == 0) {
            len = lenmax;
            char *linen = realloc(linep, lenmax *= 2);

            if(linen == NULL) {
                or_mem_free(linep);
                return NULL;
            }
            line  = linen + (line - linep);
            linep = linen;
        }

        if((*line++ = c) == '\n')
            break;
    }
    if(*(line - 1) == '\n') {
        *(line - 1) = '\0';
    }
    else {
        *line = '\0';
    }
    return linep;
}


static void or_sender_init_handshake_handler_app_data_ind(void *sessn,
                                                   OrUint8 *data,
                                                   OrUint16 dataL)
{
    OrSessionTriplet *sesn = (OrSessionTriplet *) sessn;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);


    if(sesn == NULL) {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> "
                                   "Data recvd for unknown session.",
                                   __FUNCTION__, __LINE__);
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> "
                                   "Data recvd for session %u "
                                   "from remote %s:%u",
                                   __FUNCTION__, __LINE__,
                                   sesn->sessionId, sesn->dest.ip,
                                   sesn->dest.port);

        data[dataL] = '\0';
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                   "Rcvd data from remote peer: \"%s\"", 
                                   __FUNCTION__, __LINE__, data);

        if(!strcmp(data, OR_EXPECTED_HANDHSHAKE_RSP)) {
            OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                       "We are ready to launch send app", 
                                        __FUNCTION__, __LINE__);

            OR_ASSERT((CREATE_THREAD(&orSendAppThd, 
                    NULL, or_sender_handler, NULL) < 0),
                    "or_sender_init_handshake_handler_app_data_ind> "
                    "Create thread failed.\n");
        }
    }
}

static void or_sender_app_data_ind(void *sessn,
                               OrUint8 *data,
                               OrUint16 dataL)
{
    or_mutex_lock(orSendAppDataIndLock);

    OrSessionTriplet *sesn = (OrSessionTriplet *) sessn;

    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    if(sesn == NULL) {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> "
                                   "Data recvd for unknown session.",
                                   __FUNCTION__, __LINE__);
    }
    else {
        OR_LOG(OR_LOG_LEVEL_DEBUG, "<%s (Line: %d)> "
                                   "Data recvd for session %u "
                                   "from remote %s:%u",
                                   __FUNCTION__, __LINE__,
                                   sesn->sessionId, sesn->dest.ip,
                                   sesn->dest.port);

        data[dataL] = '\0';
        OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)> "
                                   "Rcvd data from remote peer: \"%s\"", 
                                   __FUNCTION__, __LINE__, data);
    }
    or_mutex_unlock(orSendAppDataIndLock);
}

static void *or_sender_handler(void *thread_param)
{
    char c, d;
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    while(TRUE){
        printf(CLEAN_STRING);
        printf("Try Someting...\n");
        printf("1. Replay Onion\n");
        printf("2. Send a delay tolerant msg\n");
        printf("3. Send a delay intolerant msg\n");
        printf("4. Inject dummy/padding messages\n");
        printf(CLEAN_STRING);

        d = fgetc(stdin);
        while ((c = getchar()) != '\n' && c != EOF);
        if(d != '1' && d != '2'
            && d != '3' && d != '4') {
            printf("Invalid ip: %d", d);
        }
        else {
            switch(d) {
                case '1':
                {
                    or_replay_onion();
                }
                break;
                case '2':
                {
                    OrDestAddress dest;
                    char *msg = NULL;

                    printf("Enter your message:\n");

                    msg = or_getline();

                    or_mem_zero(&dest, sizeof(OrDestAddress));
                    strcpy(dest.ip, "127.0.0.1");
                    dest.port = 3003;
                    or_app_proxy_send_data(dest, OR_PROTO_SMTP, msg,
                                        strlen(msg), or_sender_app_data_ind);
                    or_mem_free(msg);
                }
                break;
                case '3':
                {
                    OrDestAddress dest;
                    char *msg = NULL;

                    printf("Enter your message:\n");

                    msg = or_getline();

                    or_mem_zero(&dest, sizeof(OrDestAddress));
                    strcpy(dest.ip, "127.0.0.1");
                    dest.port = 3003;
                    or_app_proxy_send_data(dest, OR_PROTO_SERIAL, msg,
                                        strlen(msg), or_sender_app_data_ind);
                    or_mem_free(msg);
                }
                break;
                case '4':
                {
                    OrDestAddress dest;

                    or_mem_zero(&dest, sizeof(OrDestAddress));
                    strcpy(dest.ip, "127.0.0.1");
                    dest.port = 3003;

                    or_app_proxy_send_dummy_msg(dest);
                }
                default: ;
            }//end switch(d)
        }//end if(d != '1' && d != '2' && d != '3') 
    }//end while(TRUE)

    EXIT_THREAD(NULL);
}

static void or_sender_send_initial_greetings(void)
{
    OrUint8 sendBuf[512];
    OrDestAddress dest;

    or_mem_zero(sendBuf, 512);
    or_mem_zero(&dest, sizeof(OrDestAddress));
    strcpy(dest.ip, "127.0.0.1");
    dest.port = 3003;
    strcpy(sendBuf, OR_HANDHSAKE_MSG);
    or_app_proxy_send_data(dest, OR_PROTO_SERIAL, sendBuf,
               strlen(sendBuf), or_sender_init_handshake_handler_app_data_ind);
}

/*-------------------------Public Fn Defn---------------------------------*/

void or_sender_init(void)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);

    OR_ASSERT(!or_mutex_create(&orSendAppDataIndLock), 
                "or_router_init> mutex create failed\n");

    or_sender_send_initial_greetings();
    while(!orTerminateSenderProcess);
}

void or_sender_deinit(void)
{
    OR_LOG(OR_LOG_LEVEL_DEBUG ,"<%s (Line: %d)>", __FUNCTION__, __LINE__);
    orTerminateSenderProcess = TRUE;
}
