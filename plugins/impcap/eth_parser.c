/* eth_parser.c
 *
 * This file contains functions to parse Ethernet II headers.
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

struct eth_header_s
{
	uint8_t  addrDst[6];
	uint8_t  addrSrc[6];
	uint16_t type;
} __attribute__ ((__packed__));

struct vlan_header_s
{
	uint8_t  addrDst[6];
	uint8_t  addrSrc[6];
	uint16_t vlanCode;
	uint16_t vlanTag;
	uint16_t type;
} __attribute__ ((__packed__));

typedef struct eth_header_s eth_header_t;
typedef struct vlan_header_s vlan_header_t;

/*
 *  This function parses the bytes in the received packet to extract Ethernet II metadata.
 *
 *  its parameters are:
 *    - a pointer on the list of bytes representing the packet
 *        the first byte must be the beginning of the ETH header
 *    - the size of the list passed as first parameter
 *    - a pointer on a json_object, containing all the metadata recovered so far
 *      this is also where ETH metadata will be added
 *
 *  This function returns a structure containing the data unprocessed by this parser
 *  or the ones after (as a list of bytes), and the length of this data.
*/
data_ret_t* eth_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
	DBGPRINTF("entered eth_parse\n");
	DBGPRINTF("packet size %d\n", pktSize);
	if (pktSize < 14) {  /* too short for eth header */
		DBGPRINTF("ETH packet too small : %d\n", pktSize);
		RETURN_DATA_AFTER(0)
	}

	eth_header_t *eth_header = (eth_header_t *)packet;
	char ethMacSrc[20], ethMacDst[20];
	uint8_t hdrLen = 14;

	ether_ntoa_r((struct eth_addr *)eth_header->addrSrc, ethMacSrc);
	ether_ntoa_r((struct eth_addr *)eth_header->addrDst, ethMacDst);

	json_object_object_add(jparent, "ETH_src", json_object_new_string((char*)ethMacSrc));
	json_object_object_add(jparent, "ETH_dst", json_object_new_string((char*)ethMacDst));

	uint16_t ethType = (uint16_t)ntohs(eth_header->type);

	if(ethType == ETHERTYPE_VLAN) {
		vlan_header_t *vlan_header = (vlan_header_t *)packet;
		json_object_object_add(jparent, "ETH_tag", json_object_new_int(ntohs(vlan_header->vlanTag)));
		ethType = (uint16_t)ntohs(vlan_header->type);
		hdrLen += 4;
	}

	if(ethType < 1500) {
		/* this is a LLC header */
		json_object_object_add(jparent, "ETH_len", json_object_new_int(ethType));
		return llc_parse(packet + hdrLen, pktSize - hdrLen, jparent);
	}

	json_object_object_add(jparent, "ETH_type", json_object_new_int(ethType));
	return (*ethProtoHandlers[ethType])((packet + hdrLen), (pktSize - hdrLen), jparent);
}
