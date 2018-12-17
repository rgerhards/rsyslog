#include "parser.h"

char* catch_Status_Code(char* header);
char* catch_property(char* header, char* property);

data_ret_t* http_parse(const uchar *packet,int pktSize, struct json_object *jparent){
  int oldpktSize = pktSize;
  char *http = malloc(strlen(packet) * sizeof(char));
  memcpy(http,packet,pktSize);

//  if(!strstr(packet,"HTTP")){
//     RETURN_DATA_AFTER(0)
//  }

  while(pktSize > 0) {
    if(packet[0] == 'H') {
      if(packet[1] == 'T') {
        if(packet[2] == 'T') {
          if(packet[3] == 'P'){
             break;
          }
        }
      }
    }
    packet++ , pktSize--;
  }
  if(pktSize < 6){
   packet = packet - oldpktSize;
   pktSize = oldpktSize;
   RETURN_DATA_AFTER(0)
  }

//json_object_object_add(jparent, "Http", json_object_new_string("Http"));
  
  
  char*header = strtok(http,"\r\n\r\n");
  //if(strcmp(catch_Status_Code(header),"200") == 0)
  json_object_object_add(jparent, "Http_Status_Code", json_object_new_string(catch_Status_Code(header)));
  
  
  char* property = "Content-Type:";
  char* pro = "Http_Content_Type";
  char* prop = catch_property(header, property);
  if(prop != NULL){
    json_object_object_add(jparent, pro, json_object_new_string(prop));
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
 if(strcmp(a,catch)==0){
   free(catch);
   return NULL;
 }
 char* b = strtok(NULL,"\r\n");
 free(catch);
 return b;
}
