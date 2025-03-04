#include "pe_resource_loader.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define EXPECTED_DOS_HEADER_MAGIC "MZ"
#define DOS_HEADER_MAGIC_LENGTH 2

#define AMD64 0x8664
#define i386 0x14c

#define PE32 0x10B
#define PE32PLUS 0x20B

#define EXPECTED_NT_SIGNATURE "PE"
#define NT_SIGNATURE_LENGTH 4

#define SHORT_NAME_SIZE 8

typedef struct __attribute__((packed)) {
  uint8_t  magic[2];
  uint8_t   unused[58];
  int32_t   nt_header_offset;
} DosHeader;

typedef struct __attribute__((packed)) {
  uint16_t  machine;
  uint16_t  number_of_sections;
  uint8_t   unused[16];
} FileHeader;

typedef struct __attribute__((packed)) {
  uint16_t  magic;
  uint8_t   unused1[30];
  uint32_t  section_alignment;
  uint32_t  file_alignment;
  uint8_t   unused2[52];
  uint32_t  number_of_data_directories;
} OptionalHeader;

typedef struct __attribute__((packed)) {
  uint16_t  magic;
  uint8_t   unused1[30];
  uint32_t  section_alignment;
  uint32_t  file_alignment;
  uint8_t   unused2[68];
  uint32_t  number_of_data_directories;
} OptionalHeader64;

typedef struct __attribute__((packed)) {
  uint32_t  offset;
  uint32_t  size;
} DataDirectory;

typedef struct __attribute__((packed)) {
  uint8_t  name[SHORT_NAME_SIZE];
  uint32_t  virtual_size;
  uint32_t  virtual_address;
  uint32_t  size;
  uint32_t  address;
  uint8_t   unused[16];
} SectionHeader;

typedef struct __attribute__((packed)) {
  uint8_t   unused[12];
  uint16_t  number_of_name_entries;
  uint16_t  number_of_id_entries;
} ResourceDirectoryTable;

typedef struct __attribute__((packed)) {
  uint32_t  name_offset_or_id;
  uint32_t  data_or_subdirectory_offset;
} ResourceDirectoryEntry;

typedef struct __attribute__((packed)) {
  uint32_t  offset_to_data;
  uint32_t  size;
  uint32_t  code_page;
  uint32_t  reserved;
} ResourceDataEntry;

static void validate_library() {
  // If any of these fail, you'll need to rewrite the way this library reads data to get it to work
  assert(sizeof(DosHeader) == 64);
  assert(sizeof(FileHeader) == 20);
  assert(sizeof(OptionalHeader) == 96);
  assert(sizeof(OptionalHeader64) == 112);
  assert(sizeof(DataDirectory) == 8);
  assert(sizeof(SectionHeader) == 40);
  assert(sizeof(ResourceDirectoryTable) == 16);
  assert(sizeof(ResourceDirectoryEntry) == 8);
}

PeResourceLoader * PeResourceLoader_Open(const char * file_path) {
  validate_library();  // if this fails, we cannot map the content of PE file to our structs

  PeResourceLoader * loader = (PeResourceLoader *) calloc(sizeof(PeResourceLoader), 1);
  loader->fd = fopen(file_path, "rb");
  if (loader->fd == NULL) {
    return NULL;
  }
  
  {
    // Get DOS header and verify it is a DOS header
    DosHeader dos_header;
    fread(&dos_header, sizeof(DosHeader), 1, loader->fd);
    if (strncmp(dos_header.magic, EXPECTED_DOS_HEADER_MAGIC, DOS_HEADER_MAGIC_LENGTH) != 0) {
      fclose(loader->fd);
      free(loader);
      return NULL;
    }

    // Verify NT signature
    uint8_t nt_signature[NT_SIGNATURE_LENGTH];
    fseek(loader->fd, dos_header.nt_header_offset, SEEK_SET);
    fread(nt_signature, sizeof(uint8_t), NT_SIGNATURE_LENGTH, loader->fd);
    if(strcmp(nt_signature, EXPECTED_NT_SIGNATURE) != 0) {
      fclose(loader->fd);
      free(loader);
      return NULL;
    }
  }

  {
    // Get file header and verify machine type is a supported type
    FileHeader file_header;
    fread(&file_header, sizeof(FileHeader), 1, loader->fd);
    switch (file_header.machine) {
      case i386:
        {
          // Get the number of data directories
          OptionalHeader optional_header;
          fread(&optional_header, sizeof(OptionalHeader), 1, loader->fd);
          if (optional_header.magic != PE32) {
            fclose(loader->fd);
            free(loader);
            return NULL;
          }
          // Move cursor to the section header
          fseek(loader->fd, sizeof(DataDirectory) * optional_header.number_of_data_directories, SEEK_CUR);
        }
        break;
      case AMD64:
        {
          // Get the number of data directories
          OptionalHeader64 optional_header;
          fread(&optional_header, sizeof(OptionalHeader64), 1, loader->fd);
          if (optional_header.magic != PE32PLUS) {
            PeResourceLoader_Close(loader);
            return NULL;
          }
          // Move cursor to the section header
          fseek(loader->fd, sizeof(DataDirectory) * optional_header.number_of_data_directories, SEEK_CUR);
        }
        break;
      default:
        PeResourceLoader_Close(loader);
        return NULL;
    }

    // Read the section headers
    SectionHeader * section_headers = (SectionHeader *) calloc(file_header.number_of_sections, sizeof(SectionHeader));
    fread(section_headers, sizeof(SectionHeader), file_header.number_of_sections, loader->fd);
    for(int i = 0; i < file_header.number_of_sections; i++) {
      if (strcmp(".rsrc", section_headers[i].name) == 0) {
        loader->resource_offset = section_headers[i].address;
        loader->resource_virtual_address = section_headers[i].virtual_address;
        break;
      }
    }
    if (loader->resource_offset == 0 || loader->resource_virtual_address == 0) {
      fclose(loader->fd);
      free(loader);
      return NULL;
    }
  }

  return loader;
}

PeResourceLoader * PeResourceLoader_Close(PeResourceLoader * loader) {
  fclose(loader->fd);
  free(loader);
  loader = NULL;
}