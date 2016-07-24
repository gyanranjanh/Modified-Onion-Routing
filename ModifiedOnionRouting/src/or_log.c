/*
 * FILE:	or_log.c
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#include "or_log.h"


#ifdef ENABLE_OR_LOG

static void or_log_write(OrCharString* logString, OrBool eol);
OrCharString *orLogFilePath = OR_DEFAULT_LOG_FILE_PATH;

/*-------------------------------Macro Definition------------------------*/
#define or_print__(eol, fmt, ...)         \
do {                                      \
    char s[2048];                         \
    OrCharString *logString = (char *) s; \
    va_list ap;                           \
    va_start(ap, fmt);                    \
    vsprintf(s, fmt, ap);                 \
    va_end(ap);                           \
    if(eol) {                             \
        printf("%s\n", logString);        \
    }                                     \
    else {                                \
        printf("%s", logString);          \
    }                                     \
    or_log_write(logString, eol);         \
} while(0)

/*--------------------------Local Function Definition--------------------*/
/*
 * or_log_write:
 * write to log file 
 */
static void or_log_write(OrCharString* logString, OrBool eol)
{
    OrFile *logFileStream = NULL;
    OrInt now;

    logFileStream = fopen(orLogFilePath, "a+");

    if(logFileStream == NULL)
    {
        fprintf(stderr,"<%s Line %d> can't open log-file...exiting.%s\n", 
                               __FUNCTION__, __LINE__, orLogFilePath);
        exit(1);
    }

    now = clock();

    /* write only at the end of the file */
    if(!fseek(logFileStream, 0L, SEEK_END))
    {
        if(eol) {
            fprintf(logFileStream, "%d.%06d \t%s\r\n", (OrInt)(now/CLOCKS_PER_SEC), 
                          (OrInt)((now - ((now/CLOCKS_PER_SEC)* 10^9))/(10^3)), logString);
        }
        else {
            fprintf(logFileStream, "%s", logString);
        }
    }
    else
    {
        fprintf(stderr,"<%s Line %d file seek to end failed...\n>", __FUNCTION__, __LINE__);
    }

    fclose(logFileStream);
}

/*--------------------------Global Function Definition--------------------*/
/*
 * or_log:
 * check level and write to log file 
 */
void or_log(OrUint8 level, const OrCharString *fmtString, ...)
{
    /* Debug levels are provision for future - if we want to do
     * selective logging infuture then we can use these levels
     */
    if(level == OR_LOG_LEVEL_CRITICAL || level == OR_LOG_LEVEL_ERROR
        || level == OR_LOG_LEVEL_DEBUG)
    {
        or_print__(1, fmtString);
    }
}

/*
 * or_log:
 * check level and write to log file without eol
 */
void or_log_no_eol(OrUint8 level, const OrCharString *fmtString, ...)
{
    /* Debug levels are provision for future - if we want to do
     * selective logging infuture then we can use these levels
     */
    if(level == OR_LOG_LEVEL_CRITICAL || level == OR_LOG_LEVEL_ERROR
        || level == OR_LOG_LEVEL_DEBUG)
    {
        or_print__(0, fmtString);
    }
}


/*
 * or_log_init:
 * Init OR log module
 */
void or_log_init(OrCharString *logFilePath)
{
    OrFile *logFileStream = NULL;

    orLogFilePath = logFilePath;

    logFileStream = fopen(orLogFilePath, "w+");

    if(logFileStream == NULL)
    {
        fprintf(stderr,"%s Line %d can't open log-file...exiting..\n", __FUNCTION__, __LINE__);
        exit(1);
    }

    (void)fflush(logFileStream);
    fclose(logFileStream);
}

void or_log_deinit()
{
#if 0
    if(logFileStream != NULL)
    {
        fclose(logFileStream);
    }
#endif
}
#endif
