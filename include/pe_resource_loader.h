#include <stdint.h>
#include <stdio.h>

typedef struct {
  FILE *  fd;
  uint32_t resource_virtual_address;
  uint32_t resource_offset;
} PeResourceLoader;



PeResourceLoader * PeResourceLoader_Open(const char * file_path);
PeResourceLoader * PeResourceLoader_Close(PeResourceLoader * loader);
uint32_t * PeResourceLoader_GetLanguageIds(PeResourceLoader * loader, uint16_t * language_count);
uint16_t PeResourceLoader_GetStringCount(PeResourceLoader *loader);
uint8_t * PeResourceLoader_GetString(PeResourceLoader * loader, uint16_t language_id, uint32_t string_id, uint16_t * length);