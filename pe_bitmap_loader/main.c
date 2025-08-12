#include <stdio.h>
#include <stdlib.h>

#include <pe_resource_loader.h>

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

int main(int argc, char ** argv) {
  if (argc != 2) {
    printf("No file was defined\n");
    return 1;
  }

  PeResourceLoader  * loader = PeResourceLoader_Open(argv[1]);
  if (!loader) {
    printf("File %s does not exist or is not a valid PE file\n", argv[1]);
    return 2;
  }

  uint32_t bitmap_count = 0;
  uint32_t * bitmap_ids = PeResourceLoader_GetResourceIds(loader, PRL_TYPE_BITMAP, &bitmap_count);
  if (bitmap_count == 0) {
    printf("No bitmaps found in file %s\n", argv[1]);
    PeResourceLoader_Close(loader);
    if (bitmap_ids) {
      free(bitmap_ids);
    }
    return 3;
  }

  uint16_t language_count = 0;
  uint32_t * languages = PeResourceLoader_GetLanguageIds(loader, &language_count);
  if (language_count == 0) {
    printf("No languages found in file %s\n", argv[1]);
    return 4;
  }

  for (uint16_t li = 0; li < language_count; li++) {
    printf("Language with id %u:\n", languages[li]);
    for (uint16_t bi = 0; bi < bitmap_count; bi++) {
      printf("Found bitmap with id %u\n", bitmap_ids[bi]);
      char * file_name = calloc(sizeof(char), 30);
      snprintf(file_name, 30, "%u_%u.bmp\0", languages[li], bitmap_ids[bi]);
      FILE * file = fopen(file_name, "wb");
      uint32_t file_size;
      uint8_t * data = PeResourceLoader_GetResource(loader, PRL_TYPE_BITMAP, languages[li], bitmap_ids[bi], &file_size);
      printf("File size is %u\n", file_size);
      fwrite(data, sizeof(uint8_t), file_size, file);
      fclose(file);
      free(data);
    }
    printf("\n");
  }
  free(languages);
  free(bitmap_ids);

  PeResourceLoader_Close(loader);

  return 0; 
}
