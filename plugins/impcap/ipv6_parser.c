/* ipv6_parser.c
 *
 * This file contains functions to parse IPv6 headers.
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

struct ipv6_header_s __attribute__ ((__packed__)) {
#ifndef IPV6_VERSION_MASK
	#define IPV6_VERSION_MASK 0xF0000000
#endif
#ifndef IPV6_TC_MASK
	#define IPV6_TC_MASK			0x0FF00000
#endif
#ifndef IPV6_FLOW_MASK
	#define IPV6_FLOW_MASK		0x000FFFFF
#endif
	uint32_t vtf;
	uint16_t dataLength;
	uint8_t nextHeader;
	uint8_t hopLimit;
	uint8_t addrSrc[16];
	uint8_t addrDst[16];
};

#ifndef IPV6_VERSION
	#define IPV6_VERSION(h) (ntohl(h->vtf) & IPV6_VERSION_MASK)>>28
#endif
#ifndef IPV6_TC
	#define IPV6_TC(h)			(ntohl(h->vtf) & IPV6_TC_MASK)>>20
#endif
#ifndef IPV6_FLOW
	#define IPV6_FLOW(h)		(ntohl(h->vtf) & IPV6_FLOW_MASK)
#endif

typedef struct ipv6_header_s ipv6_header_t;

/*
 *	This function parses the bytes in the received packet to extract IPv6 metadata.
 *
 *	its parameters are:
 *		- a pointer on the list of bytes representing the packet
 *				the first byte must be the beginning of the IPv6 header
 *		- the size of the list passed as first parameter
 *		- a pointer on a json_object, containing all the metadata recovered so far
 *			this is also where IPv6 metadata will be added
 *
 *	This function returns a structure containing the data unprocessed by this parser
 *	or the ones after (as a list of bytes), and the length of this data.
*/
data_ret_t* ipv6_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
	DBGPRINTF("ipv6_parse\n");
	DBGPRINTF("packet size %d\n", pktSize);

	if(pktSize < 40) { /* too small for IPv6 header + data (header might be longer)*/
		DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
		RETURN_DATA_AFTER(0)
	}

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

	char addrSrc[40], addrDst[40];

	inet_ntop(AF_INET6, (void *)&ipv6_header->addrSrc, addrSrc, 40);
	inet_ntop(AF_INET6, (void *)&ipv6_header->addrDst, addrDst, 40);

	json_object_object_add(jparent, "net_dst_ip", json_object_new_string((char*)addrDst));
	json_object_object_add(jparent, "net_src_ip", json_object_new_string((char*)addrSrc));
	json_object_object_add(jparent, "IP6_next_header", json_object_new_int(ipv6_header->nextHeader));
	json_object_object_add(jparent, "net_ttl", json_object_new_int(ipv6_header->hopLimit));

	if (ipv6_header->nextHeader == 58) {
		 return icmp_parse(packet+sizeof(ipv6_header_t),pktSize-sizeof(ipv6_header_t),jparent);
	}

	RETURN_DATA_AFTER(40)
}
