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

typedef enum {
  PRL_TYPE_CURSOR=1,
  PRL_TYPE_BITMAP=2,
  PRL_TYPE_ICON=3,
  PRL_TYPE_MENU=4,
  PRL_TYPE_DIALOG=5,
  PRL_TYPE_STRING=6,
  PRL_TYPE_FONTDIR=7,
  PRL_TYPE_FONT=8,
  PRL_TYPE_ACCELERATOR=9,
  PRL_TYPE_RCDATA=10,
  PRL_TYPE_MESSAGETABLE=11,
  PRL_TYPE_VERSION=16,
  PRL_TYPE_DLGINCLUDE=17,
  PRL_TYPE_PLUGPLAY=19,
  PRL_TYPE_VXD=20,
  PRL_TYPE_ANICURSOR=21,
  PRL_TYPE_ANIICON=22,
  PRL_TYPE_HTML=23,
  PRL_TYPE_MANIFEST=24
} PRL_Type;

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

uint32_t * PeResourceLoader_GetLanguageIds(PeResourceLoader * loader, uint16_t * language_count) {
  *language_count = 0;
  ResourceDirectoryEntry * rt_string_entry = PeResourceLoader_GetDirectoryEntryById(loader, 0, PRL_TYPE_STRING);
  if (rt_string_entry == NULL) {
    return NULL;
  }
  uint32_t * languages = (uint32_t *) calloc(MAX_LANG_COUNT, sizeof(uint32_t));

  uint16_t string_directory_count = 0;
  ResourceDirectoryEntry * string_directories = PeResourceLoader_GetDirectoryIdEntries(loader, rt_string_entry->data_or_subdirectory_offset & 0x7FFFFFFF, &string_directory_count);
  free(rt_string_entry);
  for (uint16_t string_directory_index = 0; string_directory_index < string_directory_count; string_directory_index++) {
    uint16_t language_directory_count = 0;
    ResourceDirectoryEntry * language_directories = PeResourceLoader_GetDirectoryIdEntries(loader, string_directories[string_directory_index].data_or_subdirectory_offset  & 0x7FFFFFFF, &language_directory_count);
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
  free(string_directories);

  return languages;
}

ResourceDirectoryEntry *  PeResourceLoader_GetStringDirectories(PeResourceLoader *loader, uint16_t * directory_count) {
  if (directory_count != NULL) {
    *directory_count = 0;
  }

  ResourceDirectoryEntry * rt_string_entry = PeResourceLoader_GetDirectoryEntryById(loader, 0, PRL_TYPE_STRING);
  if (rt_string_entry == NULL) {
    return NULL;
  }
  uint32_t subdirectory_offset = rt_string_entry->data_or_subdirectory_offset & 0x7FFFFFFF;
  free(rt_string_entry);

  return PeResourceLoader_GetDirectoryIdEntries(loader, subdirectory_offset, directory_count);
}

uint16_t PeResourceLoader_GetStringCount(PeResourceLoader *loader)
{
  uint16_t string_directory_count = 0;
  ResourceDirectoryEntry * string_directories = PeResourceLoader_GetStringDirectories(loader, &string_directory_count);
  uint16_t last_directory_id = 0;
  if (string_directory_count > 0) {
    last_directory_id = string_directories[string_directory_count-1].name_offset_or_id;
  }
  free(string_directories);

  return last_directory_id * 16;
}

ResourceDataEntry * PeResourceLoader_GetStringDataEntry(PeResourceLoader * loader, uint16_t language_id, uint32_t string_id) {
  uint16_t string_directory_count = 0;
  ResourceDirectoryEntry * string_directories = PeResourceLoader_GetStringDirectories(loader, &string_directory_count);

  ResourceDirectoryEntry * rt_language_entry = NULL;
  for (uint16_t string_directory_index = 0; string_directory_index < string_directory_count; string_directory_index++) {
    // The string directory id - 1 * 16 is the id of the first entry in the resource data entries in it, because each one contains 16 strings in each language in it
    if (string_directories[string_directory_index].name_offset_or_id == string_id / 16 + 1) {
      rt_language_entry = PeResourceLoader_GetDirectoryEntryById(loader, string_directories[string_directory_index].data_or_subdirectory_offset & 0x7FFFFFFF, language_id);
      break;
    }
  }
  free(string_directories);

  if (rt_language_entry == NULL) {
    return NULL;
  }

  // Need to read a resource data entry
  ResourceDataEntry * string_data_entry = calloc(sizeof(ResourceDataEntry), 1);
  fseek(loader->fd, loader->resource_offset + (rt_language_entry->data_or_subdirectory_offset & 0x7FFFFFFF), SEEK_SET);
  fread(string_data_entry, sizeof(ResourceDataEntry), 1, loader->fd);
  free(rt_language_entry);

  return string_data_entry;
}

uint8_t * PeResourceLoader_GetDataEntryData(PeResourceLoader * loader, ResourceDataEntry * data_entry) {
  if (!data_entry) {
    return NULL;
  }

  uint8_t * data = (uint8_t *) calloc(1, data_entry->size);
  uint32_t data_offset = data_entry->offset_to_data - loader->resource_virtual_address  + loader->resource_offset;

  fseek(loader->fd, data_offset, SEEK_SET);
  fread(data, 1, data_entry->size, loader->fd);

  return data;
}

uint16_t * PeResourceLoader_GetStringDataEntryData(PeResourceLoader * loader, ResourceDataEntry * data_entry) {
  // Strings are utf 16, which means it is really hard to work with when it is saved in uint8_t
  uint8_t * raw_data = PeResourceLoader_GetDataEntryData(loader, data_entry);
  uint16_t * return_data = calloc(1, data_entry->size);
  memcpy(return_data, raw_data, data_entry->size);
  free(raw_data);

  return return_data;
}

uint8_t * PeResourceLoader_Utf16ToUtf8(uint16_t * string_data, uint16_t * length) {
  uint8_t * output_string = (uint8_t *) calloc(*length + 1, sizeof(uint8_t));  // +1 for null terminator
  tmu_conversion_result result = tmu_utf8_convert_from_bytes(
    string_data,
    *length * sizeof(uint16_t),
    tmu_encoding_utf16le,
    tmu_validate_replace,
    "?",
    1,
    1,
    output_string,
    (size_t) *length + 1
  );
  if (result.ec == TM_ERANGE) {
    // If the utf-8 string is bigger than the utf16 string, retry with the new correct size
    free(output_string);
    output_string = (uint8_t *) calloc(result.size, sizeof(uint8_t));
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

uint8_t * PeResourceLoader_GetString(PeResourceLoader * loader, uint16_t language_id, uint32_t string_id, uint16_t * length) {
  if (length != NULL) {
    *length = 0;
  }

  ResourceDataEntry * string_data_entry = PeResourceLoader_GetStringDataEntry(loader, language_id, string_id);
  if (!string_data_entry) {
    return NULL;
  }

  uint16_t * data = PeResourceLoader_GetStringDataEntryData(loader, string_data_entry);

  uint16_t id = (string_id & 0xFFFFFFF0);  // The first id in a list of strings rounds to base 16
  uint16_t size = string_data_entry->size;
  free(string_data_entry);

  for(int i = 0; i < size; i++) {
      if (data[i]) {
        if (id == string_id) {
          if (length != NULL) {
            *length = data[i];
          }
          uint8_t * string = PeResourceLoader_Utf16ToUtf8(data + i + 1, &data[i]);
          free(data);

          return string;
        }
        i += data[i];
      }
      id += 1;
  }
  free(data);

  return NULL;
}
