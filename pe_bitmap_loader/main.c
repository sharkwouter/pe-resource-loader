#include <stdio.h>
#include <stdlib.h>

#include <pe_resource_loader.h>

int main(int argc, char ** argv) {
  if (argc < 2) {
    printf("No file was defined\n");
    return 1;
  }

  int return_value = 0;
  for (int i = 1; i < argc; i++) {
    printf("Bitmaps from file %s:\n", argv[i]);
    PeResourceLoader  * loader = PeResourceLoader_Open(argv[i]);
    if (!loader) {
      printf("File %s does not exist or is not a valid PE file\n", argv[i]);
      return_value = 2;
      continue;
    }

    uint16_t bitmap_count = 0;
    uint32_t * bitmap_ids = PeResourceLoader_GetResourceIds(loader, PRL_TYPE_BITMAP, &bitmap_count);
    uint16_t bitmap_name_count = 0;
    PRL_ResourceName * bitmap_names = PeResourceLoader_GetResourceNames(loader, PRL_TYPE_BITMAP, &bitmap_name_count);
    if (bitmap_count == 0 && bitmap_name_count == 0) {
      printf("No bitmaps found in file %s\n", argv[i]);
      PeResourceLoader_Close(loader);
      if (bitmap_ids) {
        free(bitmap_ids);
      }
      if (bitmap_names) {
        free(bitmap_names);
      }
      return_value = 3;
      continue;
    }

    uint16_t language_count = 0;
    uint32_t * languages = PeResourceLoader_GetLanguageIds(loader, &language_count);
    if (language_count == 0) {
      printf("No languages found in file %s\n", argv[i]);
      PeResourceLoader_Close(loader);
      if (bitmap_ids) {
        free(bitmap_ids);
      }
      if (bitmap_names) {
        free(bitmap_names);
      }
      if (languages) {
        free(languages);
      }
      return_value = 4;
      continue;
    }

    for (uint16_t li = 0; li < language_count; li++) {
      printf("Language with id %u:\n", languages[li]);
      for (uint16_t bi = 0; bi < bitmap_count; bi++) {
        uint32_t file_size = 0;
        void * data = PeResourceLoader_GetResource(loader, PRL_TYPE_BITMAP, languages[li], bitmap_ids[bi], &file_size);
        if (file_size > 0) {
          char * file_name = calloc(32 + 32 + 5, sizeof(char));
          snprintf(file_name, 32 + 32 + 5, "%u_%u.bmp", bitmap_ids[bi], languages[li]);
          printf("Exporting file %s\n", file_name);
          FILE * file = fopen(file_name, "wb");
          free(file_name);
          fwrite(data, 1, file_size, file);
          fclose(file);
        }
        if (data != NULL)
          free(data);
      }
      for (uint16_t bi = 0; bi < bitmap_name_count; bi++) {
        uint32_t file_size = 0;
        void * data = PeResourceLoader_GetNamedResource(loader, PRL_TYPE_BITMAP, languages[li], &bitmap_names[bi], &file_size);
        if (file_size > 0) {
          char * file_name = calloc(bitmap_names[bi].name_length + 32 + 4, sizeof(char));
          snprintf(file_name, bitmap_names[bi].name_length + 32 + 4, "%s_%u.bmp", bitmap_names[bi].name, languages[li]);
          printf("Exporting file %s\n", file_name);
          FILE * file = fopen(file_name, "wb");
          free(file_name);
          fwrite(data, 1, file_size, file);
          fclose(file);
        }
        if (data != NULL)
          free(data);
      }
    }
    free(languages);
    free(bitmap_ids);
    free(bitmap_names);

    PeResourceLoader_Close(loader);
  }

  return return_value;
}
