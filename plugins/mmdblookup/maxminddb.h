#ifndef MAXMINDDB_H
#define MAXMINDDB_H

typedef struct MMDB_s {
    int dummy;
} MMDB_s;

typedef struct MMDB_entry_s {
    int dummy;
} MMDB_entry_s;

typedef struct MMDB_lookup_result_s {
    int found_entry;
    MMDB_entry_s entry;
} MMDB_lookup_result_s;

typedef struct MMDB_entry_data_list_s {
    int dummy;
} MMDB_entry_data_list_s;

#define MMDB_MODE_MMAP 1
#define MMDB_SUCCESS 0
#define MMDB_IO_ERROR 1
#define MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR 2

int MMDB_open(const char *fname, int flags, MMDB_s *mmdb);
void MMDB_close(MMDB_s *mmdb);
const char *MMDB_strerror(int error_code);
MMDB_lookup_result_s MMDB_lookup_string(MMDB_s *mmdb, const char *ipstr, int *gai_error, int *mmdb_error);
int MMDB_get_entry_data_list(MMDB_entry_s *entry, MMDB_entry_data_list_s **entry_data_list);
int MMDB_dump_entry_data_list(FILE *stream, MMDB_entry_data_list_s *entry_data_list, int indent);
void MMDB_free_entry_data_list(MMDB_entry_data_list_s *entry_data_list);

#endif
