#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>

#include "rsyslog.h"
#include "errmsg.h"


#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#define FOLDERNAME "mmcapture_files"

void addDataToFile(char* pData, uint32_t sizeData, uint32_t offSet, FILE* file);
FILE* openFile(const char* path, const char* file_name);
int createFolder(char* folder);

#endif /* FILE_UTILS_H */
