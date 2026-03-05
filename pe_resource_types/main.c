#include <stdio.h>
#include <stdlib.h>

#include <pe_resource_loader.h>

int main(int argc, char ** argv) {
  if (argc < 2) {
    printf("No file was defined\n");
    return 1;
  }

  int return_value = 0;
  for(int i = 1; i < argc; i++) {
    printf("Resource types in file %s:\n", argv[i]);
    PeResourceLoader * loader = PeResourceLoader_Open(argv[i]);
    if (!loader) {
      printf("File %s does not exist or is not a valid PE file\n", argv[i]);
      return_value = 2;
      continue;
    }

    uint16_t resource_type_count = 0;
    uint32_t * resource_type_ids = PeResourceLoader_GetResourceTypes(loader, &resource_type_count);
    if (resource_type_count == 0) {
      printf("No resource types found in file %s\n", argv[i]);
      PeResourceLoader_Close(loader);
      if (resource_type_ids) {
        free(resource_type_ids);
      }
      return_value = 3;
      continue;
    }

    for (uint16_t i = 0; i < resource_type_count; i++) {
      printf("Resource type %u:\n", resource_type_ids[i]);
      uint16_t resource_count = 0;
      PRL_ResourceName * resource_names = PeResourceLoader_GetResourceNames(loader, (PRL_Type) resource_type_ids[i], &resource_count);
      for (uint16_t j = 0; j < resource_count; j++) {
        printf("%s\n", resource_names[j].name);
      }
    }
  
    free(resource_type_ids);

    PeResourceLoader_Close(loader);
  }

  return return_value;
}
