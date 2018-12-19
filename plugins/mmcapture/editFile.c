#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

void AddDataToFile(char* pointerData,int sizeData,int offSet, FILE* file ){
    fseek(file, 0, SEEK_END);
    printf("fseek : %d\n",(int)(ftell(file)));
    char zero = 0x30;
    int diff = (offSet - (int)(ftell(file)));
    if (offSet > (int)(ftell(file))){
	for(int i = 0; i < diff;i++){
	   fwrite(&zero, sizeof(char),1 ,file);
	}
    }
    fseek(file, offSet, SEEK_SET);
    fwrite(pointerData, sizeof(char),sizeData ,file);

}

FILE* OpenFile(const char* way,const char* file_name){
	DIR *dir;
	FILE *file;
	dir = opendir(way);
	if(dir != NULL){
    int ret;
    char *new_file_name;
    new_file_name = malloc(strlen(way)+1+strlen(file_name)+1);
    strcpy(new_file_name,way);
    strcat(new_file_name,file_name);
		file = fopen(new_file_name,"r+");
		if(file == NULL){
			printf("file named : %s doesn't exist\n",file_name);
			file = fopen(file_name, "w");
			if (file == NULL){
				fclose(file);
				printf("you can't create file in %s\n",way);
				return NULL;
			}
			else {
				int ret;
				char *new_file_name;
				new_file_name = malloc(strlen(way)+1+strlen(file_name)+1);
				strcpy(new_file_name,way);
				strcat(new_file_name,file_name);
				ret = rename(file_name, new_file_name);
				if(ret == 0) {
				   printf("File %s create successfully in %s\n",file_name, way);
				} else {
				  printf("Error: unable to create the file in %s\n",way);
				  return NULL;
				}
        closedir(dir);
				free(new_file_name);
      	return file;
			}
		}else{
      printf("file : %s found\n",new_file_name);
      free(new_file_name);
      closedir(dir);
      return file;
    }
	}
	else {
	       printf("Error: the folder %s doesn't exist\n",way);
	       return NULL;
	}
}




/* Exemple of AddDataToFile
int main(){
   char pointer[6] = {0x43,0x44,0x44,0x44,0x44,0x45};

   FILE *file;
   file = fopen("data_file_test","r+");
   long lenFile = fseek(file,0L,SEEK_END);

   AddData(pointer, 6 , 17, file );
   //addDataAtEndOfFile(pointer, "data_file_test",5);
   fclose(file);
   return 0;
}*/
/* Example of OpenFile
int main(){
   OpenFile("/root/Desktop/test/","mon_fichier_de_test");
   return 0;
}
*/
