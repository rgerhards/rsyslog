#include "file_utils.h"

void addDataToFile(char* pData, uint32_t sizeData, uint32_t offSet, FILE* file){
  char zero = 0x00;
  uint32_t i;

  fseek(file, 0, SEEK_END);
  DBGPRINTF("file size: %d\n",ftell(file));
  int diff = offSet - ftell(file);
  if (diff > 0){
    for(i = 0; i < diff; i++){
       fwrite(&zero, sizeof(char), 1, file);
    }
  }

  fseek(file, offSet, SEEK_SET);
  fwrite(pData, sizeof(char), sizeData, file);
}

FILE* openFile(const char* path, const char* file_name){
	DIR *dir;
	FILE *file = NULL;
  int ret;
  char *new_file_comp_path;

  assert(file_name != NULL);
  assert(path != NULL);

  DBGPRINTF("opening file %s in folder %s", file_name, path);

	dir = opendir(path);
	if(dir != NULL){
    new_file_comp_path = malloc(strlen(path)+1+strlen(file_name)+1);
    strcpy(new_file_comp_path,path);
    strcat(new_file_comp_path,file_name);

    /* assuming file is created, opening */
		file = fopen(new_file_comp_path,"r+");

		if(file == NULL){
			DBGPRINTF("file %s doesn't exist\n", file_name);
      /* creating file */
			file = fopen(new_file_comp_path, "w");
			if (file == NULL){
				DBGPRINTF("file %s couldn't be created in %s\n", file_name, path);
			}else{
        DBGPRINTF("File %s created successfully in %s\n", file_name, path);
      }
		}else{
      DBGPRINTF("existing file %s opened\n", new_file_comp_path);
    }
	}else{
    DBGPRINTF("Error: the folder %s doesn't exist\n", path);
  }

  closedir(dir);
  free(new_file_comp_path);
  return file;
}

int createFolder(char* folder){
  struct stat file_stat;
  int ret;

  assert(folder != NULL);

  ret = stat(folder, &file_stat);
  if(ret<0)
  {
    if(errno == ENOENT)
    {
      ret = mkdir(folder, 0775);

      if(ret == -1) {
        switch(errno) {
          case EACCES:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: access denied\n", folder);
                    break;
          case EEXIST:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: already exists\n", folder);
                    break;
          case ENAMETOOLONG:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: name is too long\n", folder);
                    break;
          case ENOENT:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: path doesn't exist\n", folder);
                    break;
          case ENOSPC:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: no space left on disk\n", folder);
                    break;
          case EROFS:
                    LogError(0, RS_RET_ERR,
                    "cannot create folder %s: read-only filesystem\n", folder);
                    break;
        }
        return ret;
      }
    }
  }
  return 0;
}
