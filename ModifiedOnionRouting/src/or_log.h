/*
 * FILE:	or_log.h
 * AUTHOR:	Gyanranjan Hazarika - gyanranjanh@gmail.com
 * 
 * Copyright (c) 2015-2016, Gyanranjan Hazarika
 * All rights reserved.
 *
 */

#ifndef __OR_LOG_H__
#define __OR_LOG_H__
#include "or_types.h"

#define OR_LOG_LEVEL_ERROR    0x03
#define OR_LOG_LEVEL_CRITICAL 0x02
#define OR_LOG_LEVEL_DEBUG    0x01

#ifdef ENABLE_OR_LOG

#define OR_DEFAULT_LOG_FILE_PATH "/home/gyan/Desktop/or_log.txt"

extern OrCharString *orLogFilePath;

void or_log(OrUint8 level, const OrCharString *formatString, ...);
void or_log_no_eol(OrUint8 level, const OrCharString *formatString, ...);
void or_log_init(OrCharString *logFilePath);
void or_log_deinit();

#define OR_LOG or_log
#define OR_LOG_NO_EOL or_log_no_eol

#else
#define OR_LOG(...)
#define OR_LOG_NO_EOL(...)
#endif

#endif /*__OR_LOG_H__*/
