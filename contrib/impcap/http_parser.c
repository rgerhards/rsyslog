#include "parser.h"

char* catch_Status_Code(char* header);
char* catch_property(char* header, char* property);

data_ret_t* http_parse(const uchar *packet,int pktSize, struct json_object *jparent){
  char *http = malloc(strlen(packet) * sizeof(char));
  memcpy(http,packet,pktSize);
//"^HTTP/1.[0,1] [0-9]{0,3} *"
  if(!strstr(http,"HTTP/1.")){
    RETURN_DATA_AFTER(0)
  }
  char*header = strtok(http,"\r\n\r\n");
  //if(strcmp(catch_Status_Code(header),"200") == 0)
  json_object_object_add(jparent, "Http_Status_Code", json_object_new_string(catch_Status_Code(header)));
  

  char* property = "Content-Type:";
  char* pro = "Http_Content_Type";
  if(catch_property(header, property) != NULL){
    json_object_object_add(jparent, pro, json_object_new_string(catch_property(header, property)));
  }
  int headerlength = strlen(header)+4;	
  free(http);
  RETURN_DATA_AFTER(headerlength)
  
  //char*data = strtok(NULL,"");
  //json_object_object_add(jparent, "Http_Data", json_object_new_string(data)); 
  
}

char* catch_Status_Code(char* header){ 
 char *catch = malloc(strlen(header) * sizeof(char));
 memcpy(catch,header,strlen(header));
 char* a = strtok(catch," ");
 char* b = strtok(NULL," ");
 free(catch);
 return b;
}

char* catch_property(char* header, char* property){
 char *catch = malloc(strlen(header) * sizeof(char));
 memcpy(catch,header,strlen(header));
 char* a = strtok(catch,property);
 char* b = strtok(NULL,"\r\n");
 free(catch);
 return b;
}
