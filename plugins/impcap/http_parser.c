/* http_parser.c
 *
 * This file contains functions to parse HTTP headers.
 *
 * File begun on 2018-11-13
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

#include "parser.h"

char *catch_Status_Code(char *header);

char *catch_property(char *header, char *property);

/*
 *  This function parses the bytes in the received packet to extract HTTP metadata.
 *
 *  its parameters are:
 *    - a pointer on the list of bytes representing the packet
 *        the beginning of the header will be checked by the function
 *    - the size of the list passed as first parameter
 *    - a pointer on a json_object, containing all the metadata recovered so far
 *      this is also where HTTP metadata will be added
 *
 *  This function returns a structure containing the data unprocessed by this parser
 *  or the ones after (as a list of bytes), and the length of this data.
*/
data_ret_t *http_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
	int oldpktSize = pktSize;
	char *http = malloc(strlen((const char *)packet) * sizeof(char));
	memcpy(http, packet, pktSize);

	while (pktSize > 0) {
		if (packet[0] == 'H') {
			if (packet[1] == 'T') {
				if (packet[2] == 'T') {
					if (packet[3] == 'P') {
						break;
					}
				}
			}
		}
		packet++, pktSize--;
	}
	if (pktSize < 6) {
		packet = packet - oldpktSize;
		pktSize = oldpktSize;
		RETURN_DATA_AFTER(0)
	}

	char *header = strtok(http, "\r\n\r\n");
	json_object_object_add(jparent, "Http_Status_Code", json_object_new_string(catch_Status_Code(header)));


	char *property = "Content-Type:";
	char *pro = "Http_Content_Type";
	char *prop = catch_property(header, property);
	if (prop != NULL) {
		json_object_object_add(jparent, pro, json_object_new_string(prop));
	}
	int headerlength = strlen(header) + 4;
	free(http);
	RETURN_DATA_AFTER(headerlength)
}

/*
 *  This function catches the HTTP status code
 *  and returns it or NULL if none was found
*/
char *catch_Status_Code(char *header) {
	char *catched = malloc(strlen(header) * sizeof(char));
	memcpy(catched,header, strlen(header));
	strtok(catched," ");
	char *b = strtok(NULL, " ");
	free(catched);
	return b;
}

/*
 *  This function catches a HTTP header property
 *  and returns it or NULL if none was found
*/
char *catch_property(char *header, char *property) {
	char *catched = malloc(strlen(header) * sizeof(char));
	memcpy(catched,header, strlen(header));
	char *a = strtok(catched,property);
	if (strcmp(a,catched)==0){
		free(catched);
		return NULL;
	}
	char *b = strtok(NULL, "\r\n");
	free(catched);
	return b;
}
