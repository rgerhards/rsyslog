#include "parser.h"

static const int ftp_cds[] = {
        100,110,120,125,150,
        200,202,211,212,213,214,215,220,221,225,226,227,228,229,230,231,232,250,257,
        300,331,332,350,
        400,421,425,426,430,434,450,451,452,
        500,501,502,503,504,530,532,550,551,552,553,
        600,631,632,633,
        10000,100054,10060,10061,10066,10068,
        0
};

static const char *ftp_cmds[] = {
        "STOR",
        "TYPE",
        "ABOR",
        "ACCT",
        "ALLO",
        "APPE",
        "CDUP",
        "CWD",
        "DELE",
        "HELP",
        "LIST",
        "MKD",
        "MODE",
        "NLST",
        "NOOP",
        "PASS",
        "PASV",
        "PORT",
        "PWD",
        "QUIT",
        "REIN",
        "REST",
        "RETR",
        "RMD",
        "RNFR",
        "RNTO",
        "SITE",
        "SMNT",
        "STAT",
        "STOU",
        "STRU",
        "SYST",
        "USER",
        NULL
};

// Search frst_part_ftp in ftp_cmds[]
uchar* check_Command_ftp(uchar *first_part_packet){
  DBGPRINTF("in check_Command_ftp\n");
  DBGPRINTF("first_part_packet : '%s' \n",first_part_packet);
  int i = 0;
  for(i = 0;ftp_cmds[i]!=NULL;i++ ){
    if(strcmp(first_part_packet,ftp_cmds[i]) == 0){
      return ftp_cmds[i];
    }
  }
  return NULL;
}

// Search frst_part_ftp in ftp_cds[]
int check_Code_ftp(uchar *first_part_packet){
  DBGPRINTF("in check_Code_ftp\n");
  DBGPRINTF("first_part_packet : %s \n",first_part_packet);
  int i = 0;
  for(i = 0; ftp_cds[i]!=0;i++ ){
    if(strtol(first_part_packet,NULL,10) == ftp_cds[i]){
      return ftp_cds[i];
    }
  }
  return 0;
}

data_ret_t* ftp_parse(const uchar *packet, int pktSize, struct json_object *jparent){
  DBGPRINTF("ftp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if (pktSize < 5) {  /* too short for ftp packet*/
    RETURN_DATA_AFTER(0)
    }
  uchar *packet2 = malloc(pktSize * sizeof(char));

  memcpy(packet2, packet, pktSize); // strtok change original packet
  const uchar *frst_part_ftp;
  frst_part_ftp = strtok(packet2," "); // Get first part of packet ftp
  const uchar *data_part;
  data_part = strtok(NULL,"\r\n");
  int code = check_Code_ftp(frst_part_ftp);
  uchar* command = check_Command_ftp(frst_part_ftp);
  free(packet2);
  if(code != 0){
    json_object_object_add(jparent, "response", json_object_new_int(code));
    char* code_string[6];
    sprintf(code_string,"%d",code);
    RETURN_DATA_AFTER(strlen(code_string))

  }else if(command != NULL) {
    json_object_object_add(jparent, "request", json_object_new_string(command));
    RETURN_DATA_AFTER(strlen(command)+1)

  }else{
    RETURN_DATA_AFTER(0)
  }

}
