/**
 * utility for troubleshooting rsyslog queues.
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
//#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define BUFSIZE (16*1024)
static char line[BUFSIZE];
static int lnnbr = 0;
static size_t lnlen;
static int col;
static FILE *fp;

static void
readline(void)
{
	fgets(line, sizeof(line), fp);
	lnlen = strlen(line);
	if(line[lnlen-1] == '\n') {
		line[lnlen-1] = '\0';
		--lnlen;
	}
	++lnnbr;
}

static void
errout(void)
{
	printf("\nproblem with line %d:\n%s\n", lnnbr, line);
	exit(1);
}



/* buf must be BUFSIZE large */
static void
get_str(char *buf)
{
	size_t i;
	while(line[col] != ':' && (col < lnlen)) {
		*buf++ = line[col++];
	}
	*buf = '\0';
	if(col == lnlen) {
		fprintf(stderr, "colon field terminator not found\n");
		errout();
	} else {
		col++; /* eat ':' */
	}
}

/* buf must be BUFSIZE large */
static void
get_str_with_len(char *buf, const int len)
{
	size_t i = 0;
	int done = 0;
	while(!done) {
		while(i < len && (col < lnlen)) {
			*buf++ = line[col++];
			++i;
		}
		if(i < len) {
			fprintf(stderr, "line %d has continuation line (LF): %s\n",
				lnnbr, line);
			readline();
			col = 0;
			/* process LF */
			*buf++ = '\n';
			++i;
		} else {
			done = 1;
		}
	}
	*buf = '\0';
	if(line[col] != ':') {
		fprintf(stderr, "colon field terminator not found\n");
		errout();
	} else {
		col++; /* eat ':' */
	}
}

static int
get_nbr(void)
{
	int nbr = 0;
	while(line[col] != ':' && (col < lnlen)) {
		if(!isdigit(line[col])) {
			fprintf(stderr, "non-digit found where digit was expected\n");
			errout();
		}
		nbr = nbr * 10 + line[col++] - '0';
	}
	if(col == lnlen) {
		fprintf(stderr, "colon field terminator not found\n");
		errout();
	} else {
		col++; /* eat ':' */
	}
	return nbr;
}

static void
check_prop(void)
{
	size_t i;
	static char name[BUFSIZE];
	static char data[BUFSIZE];
	int type, size;
	get_str(name);
	type = get_nbr();
	size = get_nbr();
	get_str_with_len(data, size);
	
#if 0
	printf("name:\t%s\n", name);
	printf("type:\t%d\n", type);
	printf("size:\t%d\n", size);
	printf("msg:\t%s\n", data);
#endif

	/* check unprintable chars */
	int nNonPrint = 0;
	for(i = 0 ; i < size ; ++i) {
		if(!isprint(data[i])) {
			++nNonPrint;
		}
	}
	if(nNonPrint)
		fprintf(stderr, "%d unprintable chars in line %d: %s\n",
				nNonPrint, lnnbr, line);

	if(col < lnlen) {
		fprintf(stderr, "extra data at end of property line\n");
		errout();
	}
}


static void
check_obj(FILE *fp)
{
	size_t i;
	int endobj = 0;
	readline();
	if(line[0] != '<') {
		fprintf(stderr, "invalid object start line, '<' expexted at col 1\n");
		errout();
	}
	/* we right now have a single object header, so we hardcode the
	 * check for it.
	 */
	if(strcmp(line+1, "Obj:1:msg:1:") != 0) {
		fprintf(stderr, "expected object header 'Obj:1:msg:1:' not found\n");
		errout();
	}
	while(!endobj && !feof(fp)) {
		readline();
		if(strcmp(line, ">End") == 0) {
			readline();
			if(strcmp(line, ".") == 0) {
				printf("endobj set\n");
				endobj = 1;
			} else {
				fprintf(stderr, "end object without dot line!\n");
				errout();
			}
		} else {
			if(line[0] == '+') {
				col = 1;
				check_prop();
			} else {
				fprintf(stderr, "expected character '+' not found at start of line\n");
				errout();
			}
		}
	}
	if(!endobj) {
		fprintf(stderr, "premature end of file\n");
		errout();
	}
}


void
q_check(const char *fn)
{
	fp = fopen(fn, "r");
	int nObjs = 0;
	int done = 0;

	while(!done) {
		check_obj(fp);
		++nObjs;
		if(!feof(fp)) {
			int c = fgetc(fp);
			if(c == EOF)
				done = 1;
			else
				ungetc(c, fp);
		}
	}
	printf("finished checking file of %d lines\n", lnnbr);
}


int
main(int argc, char *argv[])
{
	q_check(argv[1]);
}
