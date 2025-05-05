#include <stdio.h>
#include <stdlib.h>

#include <pe_resource_loader.h>

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

  uint32_t string_count = 0;
  uint32_t * string_ids = PeResourceLoader_GetResourceIds(loader, PRL_TYPE_STRING, &string_count);
  if (string_count == 0) {
    printf("No strings found in file %s\n", argv[1]);
    return 3;
  }

  uint16_t language_count = 0;
  uint32_t * languages = PeResourceLoader_GetLanguageIds(loader, &language_count);
  if (language_count == 0) {
    printf("No languages found in file %s\n", argv[1]);
    return 4;
  }

  for (uint16_t li = 0; li < language_count; li++) {
    printf("Strings for language with id %u:\n", languages[li]);
    for (uint16_t si = 0; si < string_count; si++) {
      uint32_t length = 0;
      uint8_t * string = PeResourceLoader_GetResource(loader, PRL_TYPE_STRING, languages[li], string_ids[si], &length);
      if (string) {
        printf("%u: %s\n", string_ids[si], string);
      }
      free(string);
    }
    printf("\n");
  }
  free(languages);

  PeResourceLoader_Close(loader);

  return 0; 
}
