#include "pe_resource_loader.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TM_UNICODE_IMPLEMENTATION
#define TMU_NO_FILE_IO
#define TMU_USE_CRT
#include "tm_unicode.h"

#define EXPECTED_DOS_HEADER_MAGIC "MZ"
#define DOS_HEADER_MAGIC_LENGTH 2

#define AMD64 0x8664
#define i386 0x14c

#define PE32 0x10B
#define PE32PLUS 0x20B

#define EXPECTED_NT_SIGNATURE "PE"
#define NT_SIGNATURE_LENGTH 4

#define SHORT_NAME_SIZE 8

#define MAX_LANG_COUNT 1024

typedef struct __attribute__((packed)) {
  uint8_t   magic[2];
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
  uint8_t   name[SHORT_NAME_SIZE];
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
    free(loader);
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
    free(section_headers);
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

ResourceDirectoryEntry * PeResourceLoader_GetDirectoryIdEntries(PeResourceLoader * loader, uint32_t offset, uint16_t * entry_count) {
  offset = loader->resource_offset + offset;

  ResourceDirectoryTable resource_directory_table;
  fseek(loader->fd, offset, SEEK_SET);
  fread(&resource_directory_table, sizeof(ResourceDirectoryTable), 1, loader->fd);
  *entry_count = resource_directory_table.number_of_id_entries;

  // Skip named entries
  fseek(loader->fd, sizeof(ResourceDirectoryEntry) * resource_directory_table.number_of_name_entries, SEEK_CUR);
  ResourceDirectoryEntry * directory_entries = (ResourceDirectoryEntry *) calloc(resource_directory_table.number_of_id_entries, sizeof(ResourceDirectoryEntry));
  fread(directory_entries, sizeof(ResourceDirectoryEntry), resource_directory_table.number_of_id_entries, loader->fd);
  return directory_entries;
}

ResourceDirectoryEntry * PeResourceLoader_GetDirectoryEntryById(PeResourceLoader * loader, uint32_t offset, uint32_t id) {
    uint16_t entry_count = 0;
    ResourceDirectoryEntry * entries = PeResourceLoader_GetDirectoryIdEntries(loader, offset, &entry_count);
    for (uint16_t i = 0; i < entry_count; i++) {
      if (entries[i].name_offset_or_id == id) {
        ResourceDirectoryEntry * entry = (ResourceDirectoryEntry *) calloc(1, sizeof(ResourceDirectoryEntry));
        memcpy(entry, &entries[i], sizeof(ResourceDirectoryEntry));
        free(entries);
        return entry;
      } 
    }

    free(entries);
    return NULL;
}

ResourceDirectoryEntry *  PeResourceLoader_GetDirectories(PeResourceLoader *loader, uint16_t * directory_count, PRL_Type type) {
  if (directory_count != NULL) {
    *directory_count = 0;
  }

  ResourceDirectoryEntry * rt_entry = PeResourceLoader_GetDirectoryEntryById(loader, 0, type);
  if (rt_entry == NULL) {
    return NULL;
  }
  uint32_t subdirectory_offset = rt_entry->data_or_subdirectory_offset & 0x7FFFFFFF;
  free(rt_entry);

  return PeResourceLoader_GetDirectoryIdEntries(loader, subdirectory_offset, directory_count);
}

ResourceDataEntry * PeResourceLoader_GetDataEntry(PeResourceLoader * loader, uint32_t language_id, uint32_t entry_id, PRL_Type type) {
  uint16_t directory_count = 0;
  ResourceDirectoryEntry * directories = PeResourceLoader_GetDirectories(loader, &directory_count, type);

  ResourceDirectoryEntry * rt_language_entry = NULL;
  for (uint16_t directory_index = 0; directory_index < directory_count; directory_index++) {
    if (directories[directory_index].name_offset_or_id == entry_id) {
      rt_language_entry = PeResourceLoader_GetDirectoryEntryById(loader, directories[directory_index].data_or_subdirectory_offset & 0x7FFFFFFF, language_id);
      break;
    }
  }
  free(directories);

  if (rt_language_entry == NULL) {
    return NULL;
  }

  // Need to read a resource data entry
  ResourceDataEntry * data_entry = calloc(sizeof(ResourceDataEntry), 1);
  fseek(loader->fd, loader->resource_offset + (rt_language_entry->data_or_subdirectory_offset & 0x7FFFFFFF), SEEK_SET);
  fread(data_entry, sizeof(ResourceDataEntry), 1, loader->fd);
  free(rt_language_entry);

  return data_entry;
}

void * PeResourceLoader_GetDataEntryData(PeResourceLoader * loader, ResourceDataEntry * data_entry) {
  if (!data_entry) {
    return NULL;
  }

  void * data = calloc(1, data_entry->size);
  uint32_t data_offset = data_entry->offset_to_data - loader->resource_virtual_address  + loader->resource_offset;

  fseek(loader->fd, data_offset, SEEK_SET);
  fread(data, 1, data_entry->size, loader->fd);

  return data;
}

void * PeResourceLoader_Utf16ToUtf8(void * string_data, size_t * length) {
  void * output_string = calloc(*length + 1, sizeof(char));  // +1 for null terminator
  tmu_conversion_result result = tmu_utf8_convert_from_bytes(
    string_data,
    *length * sizeof(uint16_t),
    tmu_encoding_utf16le,
    tmu_validate_replace,
    "?",
    1,
    1,
    output_string,
    *length + 1
  );
  if (result.ec == TM_ERANGE) {
    // If the utf-8 string is bigger than the utf16 string, retry with the new correct size
    free(output_string);
    output_string = calloc(result.size, sizeof(char));
    tmu_utf8_convert_from_bytes(
      string_data,
      *length * sizeof(uint16_t),
      tmu_encoding_utf16le,
      tmu_validate_replace,
      "?",
      1,
      1,
      output_string,
      result.size
    );
  }
  *length = result.size;
  return output_string;
}

uint32_t * PeResourceLoader_GetLanguageIds(PeResourceLoader * loader, uint16_t * language_count) {
  *language_count = 0;
  uint32_t * languages = (uint32_t *) calloc(MAX_LANG_COUNT, sizeof(uint32_t));

  uint16_t resource_table_count = 0;
  ResourceDirectoryEntry * resource_tables = PeResourceLoader_GetDirectoryIdEntries(loader, 0, &resource_table_count);
  for (uint16_t resource_table_index = 0; resource_table_index < resource_table_count; resource_table_index++) {
    uint16_t resource_directory_count = 0;
    ResourceDirectoryEntry * resource_directories = PeResourceLoader_GetDirectoryIdEntries(loader, resource_tables[resource_table_index].data_or_subdirectory_offset & 0x7FFFFFFF, &resource_directory_count);
    for (uint16_t resource_directory_index = 0; resource_directory_index < resource_directory_count; resource_directory_index++) {
      uint16_t language_directory_count = 0;
      ResourceDirectoryEntry * language_directories = PeResourceLoader_GetDirectoryIdEntries(loader, resource_directories[resource_directory_index].data_or_subdirectory_offset  & 0x7FFFFFFF, &language_directory_count);
      for (uint16_t language_directory_index = 0; language_directory_index < language_directory_count; language_directory_index++) {
        uint8_t language_found = 0;
        for(uint16_t language_index = 0; language_index < *language_count; language_index++) {
          if (language_directories[language_directory_index].name_offset_or_id == languages[language_index]) {
            language_found = 1;
              break;
            }
          }
          if (!language_found) {
            languages[*language_count] = language_directories[language_directory_index].name_offset_or_id;
            *language_count = *language_count + 1;
          }
        }
        free(language_directories);
      }
    free(resource_directories);
  }
  free(resource_tables);

  return languages;
}

uint32_t * PeResourceLoader_GetResourceIds(PeResourceLoader * loader, PRL_Type resource_type, uint32_t * count) {
  ResourceDirectoryEntry * directories = PeResourceLoader_GetDirectories(loader, (uint16_t *) count, resource_type);
  if (resource_type == PRL_TYPE_STRING) {
    *count = *count * 16;
  }
  uint32_t * resource_ids = (uint32_t *) calloc(sizeof(uint32_t), *count);
  for(uint16_t i = 0; i < *count; i++) {
    if (resource_type == PRL_TYPE_STRING) {
      resource_ids[i] = (directories[i / 16].name_offset_or_id - 1) * 16 + (i % 16);
    } else {
      resource_ids[i] = directories[i].name_offset_or_id;
    }
  }
  free(directories);

  return resource_ids;
}

void * PeResourceLoader_ProcessCursorData(PeResourceLoader * loader, void * data, uint32_t * size) {
  uint8_t cursor_header[] = {0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa8, 0x08, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00};
  void * return_data = calloc(sizeof(uint8_t), sizeof(cursor_header) + *size - 4);
  memcpy(return_data, cursor_header, sizeof(cursor_header) * sizeof(uint8_t));
  memcpy(return_data + (sizeof(cursor_header) * sizeof(uint8_t)), data + 4, *size - 4);
  free(data);

  *size = sizeof(cursor_header) * sizeof(uint8_t) + *size - 4;
  return return_data;
}

void * PeResourceLoader_ProcessIconData(PeResourceLoader * loader, void * data, uint32_t * size) {
  uint8_t icon_header[] = {0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0xa8, 0x08, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00};
  void * return_data = calloc(sizeof(uint8_t), sizeof(icon_header) + *size);
  memcpy(return_data, icon_header, sizeof(icon_header) * sizeof(uint8_t));
  memcpy(return_data + (sizeof(icon_header) * sizeof(uint8_t)), data, *size);
  free(data);

  *size = sizeof(icon_header) * sizeof(uint8_t) + *size;
  return return_data;
}

void * PeResourceLoader_ProcessBitmapData(PeResourceLoader * loader, void * data, uint32_t * size) {
  uint8_t bmp_header[] = {0x42, 0x4d, 0x38, 0xf9, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00};
  void * return_data = calloc(sizeof(uint8_t), sizeof(bmp_header) + *size);
  memcpy(return_data, bmp_header, sizeof(bmp_header) * sizeof(uint8_t));
  memcpy(return_data + (sizeof(bmp_header) * sizeof(uint8_t)), data, *size);
  free(data);

  *size = sizeof(bmp_header) * sizeof(uint8_t) + *size;
  return return_data;
}

void * PeResourceLoader_ProcessStringData(PeResourceLoader * loader, uint32_t string_id, void * data, uint32_t * size) {
  if (!data || *size <= 0) {
    *size = 0;
    return NULL;
  }

  uint32_t id = (string_id & 0xFFFFFFFFFFFFFFF0);  // The first id in a list of strings rounds to base 16

  void * string = NULL;
  for(int i = 0; i < (*size / sizeof(uint16_t)); i++) {
      if (((uint16_t *) data)[i]) {
        if (id == string_id) {
          size_t length = (size_t) ((uint16_t *) data)[i];
          string = PeResourceLoader_Utf16ToUtf8(((uint16_t *) data) + i + 1, &length);
          *size = length;

          free(data);
          return string;
        }
        i += ((uint16_t *) data)[i];
      }
      id += 1;
  }
  free(data);

  return string;
}

void * PeResourceLoader_ProcessResourceData(PeResourceLoader * loader, PRL_Type resource_type, void * data, uint32_t * size, uint32_t string_id) {
  switch (resource_type) {
    case PRL_TYPE_STRING:
      data = PeResourceLoader_ProcessStringData(loader, string_id, data, size);
      break;
    case PRL_TYPE_BITMAP:
      data = PeResourceLoader_ProcessBitmapData(loader, data, size);
      break;
    case PRL_TYPE_ICON:
      data = PeResourceLoader_ProcessIconData(loader, data, size);
      break;
    case PRL_TYPE_CURSOR:
      data = PeResourceLoader_ProcessCursorData(loader, data, size);
      break;
    default:
      break;
  }
  return data;
}


void * PeResourceLoader_GetResource(PeResourceLoader * loader, PRL_Type resource_type, uint32_t language_id, uint32_t resource_id, uint32_t * size) {
  if (size != NULL) {
    *size = 0;
  }
  
  uint32_t string_id = 0;
  if(resource_type == PRL_TYPE_STRING) {
    string_id = resource_id;
    resource_id = resource_id / 16 + 1;
  }

  ResourceDataEntry * data_entry = PeResourceLoader_GetDataEntry(loader, language_id, resource_id, resource_type);
  if (!data_entry) {
    return NULL;
  }

  void * data = PeResourceLoader_GetDataEntryData(loader, data_entry);
  if (!data) {
    free(data_entry);
    return NULL;
  }

  if (size != NULL) {
    *size = data_entry->size;
    free(data_entry);
    data = PeResourceLoader_ProcessResourceData(loader, resource_type, data, size, string_id);
  } else {
    uint32_t temp_size = data_entry->size;
    free(data_entry);
    data = PeResourceLoader_ProcessResourceData(loader, resource_type, data, &temp_size, string_id);
  }

  return data;
}
