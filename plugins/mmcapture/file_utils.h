/* file_utils.h
 *
 * This header contains prototypes for file_utils.c,
 * being functions to manage files
 *
 * File begun on 2018-12-5
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

void addDataToFile(char* pData, uint32_t sizeData, uint32_t offSet, FILE* file);
FILE* openFile(const char* path, const char* file_name);
int createFolder(char* folder);

#endif /* FILE_UTILS_H */
