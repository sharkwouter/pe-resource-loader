#include "pe_resource_loader.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef DEBUG
  #include <assert.h>
#endif

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
#define MAX_SECTION_COUNT 1024
#define MAX_RESOURCE_NAME_UTF16_LENGTH 4096

static const uint8_t PRL_EXPECTED_NT_SIGNATURE[NT_SIGNATURE_LENGTH] = {'P', 'E', 0x00, 0x00};
static const uint8_t PRL_RSRC_SECTION_NAME[SHORT_NAME_SIZE] = {'.', 'r', 's', 'r', 'c', 0x00, 0x00, 0x00};

typedef struct __attribute__((packed)) {
  uint8_t   magic[2];
  uint8_t   unused[58];
  int32_t   nt_header_offset;
} PRL_DosHeader;

typedef struct __attribute__((packed)) {
  uint16_t  machine;
  uint16_t  number_of_sections;
  uint8_t   unused[16];
} PRL_FileHeader;

typedef struct __attribute__((packed)) {
  uint16_t  magic;
  uint8_t   unused1[30];
  uint32_t  section_alignment;
  uint32_t  file_alignment;
  uint8_t   unused2[52];
  uint32_t  number_of_data_directories;
} PRL_OptionalHeader;

typedef struct __attribute__((packed)) {
  uint16_t  magic;
  uint8_t   unused1[30];
  uint32_t  section_alignment;
  uint32_t  file_alignment;
  uint8_t   unused2[68];
  uint32_t  number_of_data_directories;
} PRL_OptionalHeader64;

typedef struct __attribute__((packed)) {
  uint32_t  offset;
  uint32_t  size;
} PRL_DataDirectory;

typedef struct __attribute__((packed)) {
  uint8_t   name[SHORT_NAME_SIZE];
  uint32_t  virtual_size;
  uint32_t  virtual_address;
  uint32_t  size;
  uint32_t  address;
  uint8_t   unused[16];
} PRL_SectionHeader;

typedef struct __attribute__((packed)) {
  uint8_t   unused[12];
  uint16_t  number_of_name_entries;
  uint16_t  number_of_id_entries;
} PRL_ResourceDirectoryTable;

typedef struct __attribute__((packed)) {
  uint32_t  name_offset_or_id;
  uint32_t  data_or_subdirectory_offset;
} PRL_ResourceDirectoryEntry;

typedef struct __attribute__((packed)) {
  uint32_t  offset_to_data;
  uint32_t  size;
  uint32_t  code_page;
  uint32_t  reserved;
} PE_ResourceDataEntry;

static uint8_t prl_get_file_size(FILE * fd, uint64_t * file_size) {
  if (!fd || !file_size) {
    return 0;
  }

  long current_position = ftell(fd);
  if (current_position < 0) {
    return 0;
  }

  if (fseek(fd, 0, SEEK_END) != 0) {
    return 0;
  }

  long end_position = ftell(fd);
  if (end_position < 0) {
    return 0;
  }

  if (fseek(fd, current_position, SEEK_SET) != 0) {
    return 0;
  }

  *file_size = (uint64_t) end_position;
  return 1;
}

static uint8_t prl_is_range_valid(uint64_t file_size, uint64_t offset, uint64_t size) {
  return offset <= file_size && size <= (file_size - offset);
}

static uint8_t prl_seek_exact(FILE * fd, uint64_t offset) {
  if (!fd || offset > LONG_MAX) {
    return 0;
  }

  return fseek(fd, (long) offset, SEEK_SET) == 0;
}

static uint8_t prl_read_exact(FILE * fd, void * data, size_t size, size_t count) {
  if (!fd || (!data && size > 0 && count > 0)) {
    return 0;
  }

  return fread(data, size, count, fd) == count;
}

static uint8_t prl_read_at(FILE * fd, uint64_t file_size, uint64_t offset, void * data, size_t size) {
  if (size == 0) {
    return 1;
  }

  if (!prl_is_range_valid(file_size, offset, size)) {
    return 0;
  }

  if (!prl_seek_exact(fd, offset)) {
    return 0;
  }

  return prl_read_exact(fd, data, 1, size);
}

static uint8_t prl_add_u64(uint64_t a, uint64_t b, uint64_t * result) {
  if (!result || a > UINT64_MAX - b) {
    return 0;
  }
  *result = a + b;
  return 1;
}

static uint8_t prl_is_rsrc_section(const uint8_t name[SHORT_NAME_SIZE]) {
  return memcmp(name, PRL_RSRC_SECTION_NAME, SHORT_NAME_SIZE) == 0;
}

#ifdef DEBUG
  static void validate_library() {
    // If any of these fail, you'll need to rewrite the way this library reads data to get it to work
    assert(sizeof(PRL_DosHeader) == 64);
    assert(sizeof(PRL_FileHeader) == 20);
    assert(sizeof(PRL_OptionalHeader) == 96);
    assert(sizeof(PRL_OptionalHeader64) == 112);
    assert(sizeof(PRL_DataDirectory) == 8);
    assert(sizeof(PRL_SectionHeader) == 40);
    assert(sizeof(PRL_ResourceDirectoryTable) == 16);
    assert(sizeof(PRL_ResourceDirectoryEntry) == 8);
  }
#endif

PeResourceLoader * PeResourceLoader_Open(const char * file_path) {
  #ifdef DEBUG
    validate_library();  // if this fails, we cannot map the content of PE file to our structs
  #endif

  if (!file_path) {
    return NULL;
  }

  PeResourceLoader * loader = (PeResourceLoader *) calloc(1, sizeof(PeResourceLoader));
  if (!loader) {
    return NULL;
  }

  loader->fd = fopen(file_path, "rb");
  if (loader->fd == NULL) {
    free(loader);
    return NULL;
  }

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    PeResourceLoader_Close(loader);
    return NULL;
  }
  
  {
    // Get DOS header and verify it is a DOS header
    PRL_DosHeader dos_header;
    if (!prl_read_at(loader->fd, file_size, 0, &dos_header, sizeof(PRL_DosHeader))) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    if (memcmp(dos_header.magic, EXPECTED_DOS_HEADER_MAGIC, DOS_HEADER_MAGIC_LENGTH) != 0) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    if (dos_header.nt_header_offset < 0) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    uint64_t nt_header_offset = (uint64_t) dos_header.nt_header_offset;
    if (!prl_is_range_valid(file_size, nt_header_offset, NT_SIGNATURE_LENGTH + sizeof(PRL_FileHeader))) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    // Verify NT signature
    uint8_t nt_signature[NT_SIGNATURE_LENGTH];
    if (!prl_read_at(loader->fd, file_size, nt_header_offset, nt_signature, sizeof(nt_signature))) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    if (memcmp(nt_signature, PRL_EXPECTED_NT_SIGNATURE, NT_SIGNATURE_LENGTH) != 0) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    // Get file header and verify machine type is a supported type
    PRL_FileHeader file_header;
    uint64_t file_header_offset = nt_header_offset + NT_SIGNATURE_LENGTH;
    if (!prl_read_at(loader->fd, file_size, file_header_offset, &file_header, sizeof(PRL_FileHeader))) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    if (file_header.number_of_sections == 0 || file_header.number_of_sections > MAX_SECTION_COUNT) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    uint64_t section_headers_offset = file_header_offset + sizeof(PRL_FileHeader);
    switch (file_header.machine) {
      case i386:
        {
          // Get the number of data directories
          PRL_OptionalHeader optional_header;
          if (!prl_read_at(loader->fd, file_size, section_headers_offset, &optional_header, sizeof(PRL_OptionalHeader))) {
            PeResourceLoader_Close(loader);
            return NULL;
          }

          if (optional_header.magic != PE32) {
            PeResourceLoader_Close(loader);
            return NULL;
          }

          section_headers_offset += sizeof(PRL_OptionalHeader);
          uint64_t data_directories_size = (uint64_t) optional_header.number_of_data_directories * sizeof(PRL_DataDirectory);
          if (!prl_add_u64(section_headers_offset, data_directories_size, &section_headers_offset)) {
            PeResourceLoader_Close(loader);
            return NULL;
          }
        }
        break;
      case AMD64:
        {
          // Get the number of data directories
          PRL_OptionalHeader64 optional_header;
          if (!prl_read_at(loader->fd, file_size, section_headers_offset, &optional_header, sizeof(PRL_OptionalHeader64))) {
            PeResourceLoader_Close(loader);
            return NULL;
          }

          if (optional_header.magic != PE32PLUS) {
            PeResourceLoader_Close(loader);
            return NULL;
          }

          section_headers_offset += sizeof(PRL_OptionalHeader64);
          uint64_t data_directories_size = (uint64_t) optional_header.number_of_data_directories * sizeof(PRL_DataDirectory);
          if (!prl_add_u64(section_headers_offset, data_directories_size, &section_headers_offset)) {
            PeResourceLoader_Close(loader);
            return NULL;
          }
        }
        break;
      default:
        PeResourceLoader_Close(loader);
        return NULL;
    }

    uint64_t section_headers_size = (uint64_t) file_header.number_of_sections * sizeof(PRL_SectionHeader);
    if (!prl_is_range_valid(file_size, section_headers_offset, section_headers_size)) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    // Read the section headers
    PRL_SectionHeader * section_headers = (PRL_SectionHeader *) calloc(file_header.number_of_sections, sizeof(PRL_SectionHeader));
    if (!section_headers) {
      PeResourceLoader_Close(loader);
      return NULL;
    }

    if (!prl_read_at(loader->fd, file_size, section_headers_offset, section_headers, (size_t) section_headers_size)) {
      free(section_headers);
      PeResourceLoader_Close(loader);
      return NULL;
    }

    for(int i = 0; i < file_header.number_of_sections; i++) {
      if (prl_is_rsrc_section(section_headers[i].name)) {
        uint64_t resource_end = 0;
        if (!prl_add_u64(section_headers[i].address, section_headers[i].size, &resource_end)) {
          break;
        }

        if (section_headers[i].address >= file_size || resource_end > file_size) {
          break;
        }

        loader->resource_offset = section_headers[i].address;
        loader->resource_virtual_address = section_headers[i].virtual_address;
        break;
      }
    }
    free(section_headers);
    if (loader->resource_offset == 0 || loader->resource_virtual_address == 0) {
      PeResourceLoader_Close(loader);
      return NULL;
    }
  }

  return loader;
}

void PeResourceLoader_Close(PeResourceLoader * loader) {
  if (!loader) {
    return;
  }

  if (loader->fd) {
    fclose(loader->fd);
  }
  free(loader);
}

PRL_ResourceDirectoryEntry * PeResourceLoader_GetDirectoryNamedEntries(PeResourceLoader * loader, uint32_t offset, uint16_t * entry_count) {
  if (!loader || !loader->fd || !entry_count) {
    return NULL;
  }

  *entry_count = 0;

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    return NULL;
  }

  uint64_t directory_table_offset = 0;
  if (!prl_add_u64(loader->resource_offset, offset, &directory_table_offset)) {
    return NULL;
  }

  PRL_ResourceDirectoryTable resource_directory_table;
  if (!prl_read_at(loader->fd, file_size, directory_table_offset, &resource_directory_table, sizeof(PRL_ResourceDirectoryTable))) {
    return NULL;
  }

  if (resource_directory_table.number_of_name_entries == 0) {
    return NULL;
  }

  uint64_t entries_size = (uint64_t) resource_directory_table.number_of_name_entries * sizeof(PRL_ResourceDirectoryEntry);
  uint64_t entries_offset = directory_table_offset + sizeof(PRL_ResourceDirectoryTable);
  if (!prl_is_range_valid(file_size, entries_offset, entries_size)) {
    return NULL;
  }

  PRL_ResourceDirectoryEntry * directory_entries = (PRL_ResourceDirectoryEntry *) calloc(resource_directory_table.number_of_name_entries, sizeof(PRL_ResourceDirectoryEntry));
  if (!directory_entries) {
    return NULL;
  }

  if (!prl_read_at(loader->fd, file_size, entries_offset, directory_entries, (size_t) entries_size)) {
    free(directory_entries);
    return NULL;
  }

  *entry_count = resource_directory_table.number_of_name_entries;
  return directory_entries;
}

PRL_ResourceDirectoryEntry * PeResourceLoader_GetDirectoryIdEntries(PeResourceLoader * loader, uint32_t offset, uint16_t * entry_count) {
  if (!loader || !loader->fd || !entry_count) {
    return NULL;
  }

  *entry_count = 0;

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    return NULL;
  }

  uint64_t directory_table_offset = 0;
  if (!prl_add_u64(loader->resource_offset, offset, &directory_table_offset)) {
    return NULL;
  }

  PRL_ResourceDirectoryTable resource_directory_table;
  if (!prl_read_at(loader->fd, file_size, directory_table_offset, &resource_directory_table, sizeof(PRL_ResourceDirectoryTable))) {
    return NULL;
  }

  if (resource_directory_table.number_of_id_entries == 0) {
    return NULL;
  }

  uint64_t named_entries_size = (uint64_t) resource_directory_table.number_of_name_entries * sizeof(PRL_ResourceDirectoryEntry);
  uint64_t entries_size = (uint64_t) resource_directory_table.number_of_id_entries * sizeof(PRL_ResourceDirectoryEntry);
  uint64_t entries_offset = directory_table_offset + sizeof(PRL_ResourceDirectoryTable);
  if (!prl_add_u64(entries_offset, named_entries_size, &entries_offset)) {
    return NULL;
  }
  if (!prl_is_range_valid(file_size, entries_offset, entries_size)) {
    return NULL;
  }

  PRL_ResourceDirectoryEntry * directory_entries = (PRL_ResourceDirectoryEntry *) calloc(resource_directory_table.number_of_id_entries, sizeof(PRL_ResourceDirectoryEntry));
  if (!directory_entries) {
    return NULL;
  }

  if (!prl_read_at(loader->fd, file_size, entries_offset, directory_entries, (size_t) entries_size)) {
    free(directory_entries);
    return NULL;
  }

  *entry_count = resource_directory_table.number_of_id_entries;
  return directory_entries;
}

PRL_ResourceDirectoryEntry * PeResourceLoader_GetDirectoryEntries(PeResourceLoader * loader, uint32_t offset, uint16_t * entry_count) {
  if (!loader || !loader->fd || !entry_count) {
    return NULL;
  }

  *entry_count = 0;

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    return NULL;
  }

  uint64_t directory_table_offset = 0;
  if (!prl_add_u64(loader->resource_offset, offset, &directory_table_offset)) {
    return NULL;
  }

  PRL_ResourceDirectoryTable resource_directory_table;
  if (!prl_read_at(loader->fd, file_size, directory_table_offset, &resource_directory_table, sizeof(PRL_ResourceDirectoryTable))) {
    return NULL;
  }

  uint32_t total_entries = (uint32_t) resource_directory_table.number_of_name_entries + (uint32_t) resource_directory_table.number_of_id_entries;
  if (total_entries == 0 || total_entries > UINT16_MAX) {
    return NULL;
  }

  uint64_t entries_size = (uint64_t) total_entries * sizeof(PRL_ResourceDirectoryEntry);
  uint64_t entries_offset = directory_table_offset + sizeof(PRL_ResourceDirectoryTable);
  if (!prl_is_range_valid(file_size, entries_offset, entries_size)) {
    return NULL;
  }

  PRL_ResourceDirectoryEntry * directory_entries = (PRL_ResourceDirectoryEntry *) calloc(total_entries, sizeof(PRL_ResourceDirectoryEntry));
  if (!directory_entries) {
    return NULL;
  }

  if (!prl_read_at(loader->fd, file_size, entries_offset, directory_entries, (size_t) entries_size)) {
    free(directory_entries);
    return NULL;
  }

  *entry_count = (uint16_t) total_entries;
  return directory_entries;
}

PRL_ResourceDirectoryEntry * PeResourceLoader_GetDirectoryEntryById(PeResourceLoader * loader, uint32_t offset, uint32_t id) {
    uint16_t entry_count = 0;
    PRL_ResourceDirectoryEntry * entries = PeResourceLoader_GetDirectoryEntries(loader, offset, &entry_count);
    if (!entries || entry_count == 0) {
      free(entries);
      return NULL;
    }
    for (uint16_t i = 0; i < entry_count; i++) {
      if (entries[i].name_offset_or_id == id) {
        PRL_ResourceDirectoryEntry * entry = (PRL_ResourceDirectoryEntry *) calloc(1, sizeof(PRL_ResourceDirectoryEntry));
        if (!entry) {
          free(entries);
          return NULL;
        }
        memcpy(entry, &entries[i], sizeof(PRL_ResourceDirectoryEntry));
        free(entries);
        return entry;
      } 
    }

    free(entries);
    return NULL;
}

PRL_ResourceDirectoryEntry *  PeResourceLoader_GetDirectories(PeResourceLoader *loader, uint16_t * directory_count, PRL_Type type) {
  if (!loader || !loader->fd || !directory_count) {
    return NULL;
  }

  if (directory_count != NULL) {
    *directory_count = 0;
  }

  PRL_ResourceDirectoryEntry * rt_entry = PeResourceLoader_GetDirectoryEntryById(loader, 0, type);
  if (rt_entry == NULL) {
    return NULL;
  }
  uint32_t subdirectory_offset = rt_entry->data_or_subdirectory_offset & 0x7FFFFFFF;
  free(rt_entry);

  return PeResourceLoader_GetDirectoryEntries(loader, subdirectory_offset, directory_count);
}

PE_ResourceDataEntry * PeResourceLoader_GetDataEntry(PeResourceLoader * loader, uint32_t language_id, uint32_t entry_id, PRL_Type type) {
  if (!loader || !loader->fd) {
    return NULL;
  }

  uint16_t directory_count = 0;
  PRL_ResourceDirectoryEntry * directories = PeResourceLoader_GetDirectories(loader, &directory_count, type);
  if (!directories || directory_count == 0) {
    free(directories);
    return NULL;
  }

  PRL_ResourceDirectoryEntry * rt_language_entry = NULL;
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
  PE_ResourceDataEntry * data_entry = calloc(1, sizeof(PE_ResourceDataEntry));
  if (!data_entry) {
    free(rt_language_entry);
    return NULL;
  }

  uint64_t file_size = 0;
  uint64_t data_entry_offset = 0;
  if (!prl_get_file_size(loader->fd, &file_size)
    || !prl_add_u64(loader->resource_offset, rt_language_entry->data_or_subdirectory_offset & 0x7FFFFFFF, &data_entry_offset)
    || !prl_read_at(loader->fd, file_size, data_entry_offset, data_entry, sizeof(PE_ResourceDataEntry))) {
    free(rt_language_entry);
    free(data_entry);
    return NULL;
  }

  free(rt_language_entry);

  return data_entry;
}

void * PeResourceLoader_GetDataEntryData(PeResourceLoader * loader, PE_ResourceDataEntry * data_entry) {
  if (!loader || !loader->fd || !data_entry || data_entry->size == 0) {
    return NULL;
  }

  if (data_entry->offset_to_data < loader->resource_virtual_address) {
    return NULL;
  }

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    return NULL;
  }

  uint64_t data_offset = 0;
  if (!prl_add_u64(
    loader->resource_offset,
    (uint64_t) data_entry->offset_to_data - loader->resource_virtual_address,
    &data_offset)
  ) {
    return NULL;
  }

  if (!prl_is_range_valid(file_size, data_offset, data_entry->size)) {
    return NULL;
  }

  void * data = calloc(1, data_entry->size);
  if (!data) {
    return NULL;
  }

  if (!prl_read_at(loader->fd, file_size, data_offset, data, data_entry->size)) {
    free(data);
    return NULL;
  }

  return data;
}

void * PeResourceLoader_Utf16ToUtf8(void * string_data, uint16_t * length) {
  if (!length) {
    return NULL;
  }

  if (*length == 0) {
    void * empty_string = calloc(1, sizeof(char));
    return empty_string;
  }

  if (!string_data) {
    *length = 0;
    return NULL;
  }

  void * output_string = calloc((size_t) *length + 1, sizeof(char));  // +1 for null terminator
  if (!output_string) {
    *length = 0;
    return NULL;
  }

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
    if (!output_string) {
      *length = 0;
      return NULL;
    }
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

  if (result.size > UINT16_MAX) {
    free(output_string);
    *length = 0;
    return NULL;
  }

  *length = (uint16_t) result.size;
  return output_string;
}

uint32_t * PeResourceLoader_GetLanguageIds(PeResourceLoader * loader, uint16_t * language_count) {
  if (!loader || !loader->fd || !language_count) {
    return NULL;
  }

  *language_count = 0;
  uint32_t * languages = (uint32_t *) calloc(MAX_LANG_COUNT, sizeof(uint32_t));
  if (!languages) {
    return NULL;
  }

  uint16_t resource_table_count = 0;
  PRL_ResourceDirectoryEntry * resource_tables = PeResourceLoader_GetDirectoryIdEntries(loader, 0, &resource_table_count);
  if (resource_table_count > 0 && !resource_tables) {
    free(languages);
    return NULL;
  }
  for (uint16_t resource_table_index = 0; resource_table_index < resource_table_count; resource_table_index++) {
    uint16_t resource_directory_count = 0;
    PRL_ResourceDirectoryEntry * resource_directories = PeResourceLoader_GetDirectoryEntries(loader, resource_tables[resource_table_index].data_or_subdirectory_offset & 0x7FFFFFFF, &resource_directory_count);
    if (resource_directory_count > 0 && !resource_directories) {
      free(resource_tables);
      free(languages);
      return NULL;
    }
    for (uint16_t resource_directory_index = 0; resource_directory_index < resource_directory_count; resource_directory_index++) {
      uint16_t language_directory_count = 0;
      PRL_ResourceDirectoryEntry * language_directories = PeResourceLoader_GetDirectoryIdEntries(loader, resource_directories[resource_directory_index].data_or_subdirectory_offset  & 0x7FFFFFFF, &language_directory_count);
      if (language_directory_count > 0 && !language_directories) {
        free(resource_directories);
        free(resource_tables);
        free(languages);
        return NULL;
      }
      for (uint16_t language_directory_index = 0; language_directory_index < language_directory_count; language_directory_index++) {
        uint8_t language_found = 0;
        for(uint16_t language_index = 0; language_index < *language_count; language_index++) {
          if (language_directories[language_directory_index].name_offset_or_id == languages[language_index]) {
            language_found = 1;
              break;
            }
          }
          if (!language_found) {
            if (*language_count >= MAX_LANG_COUNT) {
              free(language_directories);
              free(resource_directories);
              free(resource_tables);
              return languages;
            }
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

uint32_t * PeResourceLoader_GetResourceIds(PeResourceLoader * loader, PRL_Type resource_type, uint16_t * count) {
  if (!loader || !loader->fd || !count) {
    return NULL;
  }

  PRL_ResourceDirectoryEntry * directories = PeResourceLoader_GetDirectories(loader, count, resource_type);
  if (*count > 0 && !directories) {
    return NULL;
  }

  uint16_t directory_count = *count;
  uint32_t result_count = directory_count;
  if (resource_type == PRL_TYPE_STRING) {
    result_count = (uint32_t) directory_count * 16;
    if (result_count > UINT16_MAX) {
      free(directories);
      *count = 0;
      return NULL;
    }
  }

  *count = (uint16_t) result_count;
  if (*count == 0) {
    free(directories);
    return NULL;
  }

  uint32_t * resource_ids = (uint32_t *) calloc(*count, sizeof(uint32_t));
  if (!resource_ids) {
    free(directories);
    *count = 0;
    return NULL;
  }

  for(uint16_t i = 0; i < *count; i++) {
    if (resource_type == PRL_TYPE_STRING) {
      uint16_t directory_index = i / 16;
      if (directories[directory_index].name_offset_or_id & 0x80000000) {
        continue;
      }

      if (directories[directory_index].name_offset_or_id > 0) {
        resource_ids[i] = (directories[directory_index].name_offset_or_id - 1) * 16 + (i % 16);
      }
    } else {
      // Skip named entries
      if (directories[i].name_offset_or_id & 0x80000000) {
        continue;
      }
      resource_ids[i] = directories[i].name_offset_or_id;
    }
  }
  free(directories);

  return resource_ids;
}

PRL_ResourceName * PeResourceLoader_GetResourceNames(PeResourceLoader *loader, PRL_Type resource_type, uint16_t *count) {
  if (!loader || !loader->fd || !count) {
    return NULL;
  }

  if (*count != 0) {
    *count = 0;
  }

  PRL_ResourceDirectoryEntry * rt_entry = PeResourceLoader_GetDirectoryEntryById(loader, 0, resource_type);
  if (rt_entry == NULL) {
    return NULL;
  }
  uint32_t subdirectory_offset = rt_entry->data_or_subdirectory_offset & 0x7FFFFFFF;
  free(rt_entry);

  PRL_ResourceDirectoryEntry * resource_entries = PeResourceLoader_GetDirectoryNamedEntries(loader, subdirectory_offset, count);
  if (*count == 0 || !resource_entries) {
    free(resource_entries);
    return NULL;
  }
  PRL_ResourceName * resource_names = (PRL_ResourceName *) calloc(*count, sizeof(PRL_ResourceName));
  if (!resource_names) {
    free(resource_entries);
    return NULL;
  }

  uint64_t file_size = 0;
  if (!prl_get_file_size(loader->fd, &file_size)) {
    free(resource_entries);
    free(resource_names);
    return NULL;
  }

  for (uint16_t i = 0; i < *count; i++) {
    resource_names[i].name_offset_or_id = resource_entries[i].name_offset_or_id;
    uint64_t name_offset = 0;
    if (!prl_add_u64(loader->resource_offset, resource_entries[i].name_offset_or_id & 0x7FFFFFFF, &name_offset)
      || !prl_read_at(loader->fd, file_size, name_offset, &resource_names[i].name_length, sizeof(uint16_t))
      || resource_names[i].name_length > MAX_RESOURCE_NAME_UTF16_LENGTH) {
      goto error_cleanup;
    }

    uint64_t utf16_bytes = (uint64_t) resource_names[i].name_length * sizeof(uint16_t);
    uint64_t utf16_offset = name_offset + sizeof(uint16_t);
    if (!prl_is_range_valid(file_size, utf16_offset, utf16_bytes)) {
      goto error_cleanup;
    }

    uint16_t * utf16_string = (uint16_t *) calloc(resource_names[i].name_length > 0 ? resource_names[i].name_length : 1, sizeof(uint16_t));
    if (!utf16_string) {
      goto error_cleanup;
    }

    if (!prl_read_at(loader->fd, file_size, utf16_offset, utf16_string, (size_t) utf16_bytes)) {
      free(utf16_string);
      goto error_cleanup;
    }

    resource_names[i].name = (char *) PeResourceLoader_Utf16ToUtf8(utf16_string, &resource_names[i].name_length);
    free(utf16_string);
    if (!resource_names[i].name) {
      goto error_cleanup;
    }
  }

  free(resource_entries);
  return resource_names;

error_cleanup:
  free(resource_entries);
  for (uint16_t i = 0; i < *count; i++) {
    free(resource_names[i].name);
  }
  free(resource_names);
  *count = 0;
  return NULL;
}

void * PeResourceLoader_ProcessCursorData(void * data, uint32_t * size) {
  if (!data || !size || *size < 4) {
    free(data);
    if (size) {
      *size = 0;
    }
    return NULL;
  }

  uint8_t cursor_header[] = {0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa8, 0x08, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00};
  uint64_t return_size = sizeof(cursor_header) + ((uint64_t) *size - 4);
  if (return_size > SIZE_MAX) {
    free(data);
    *size = 0;
    return NULL;
  }

  void * return_data = calloc((size_t) return_size, sizeof(uint8_t));
  if (!return_data) {
    free(data);
    *size = 0;
    return NULL;
  }
  memcpy(return_data, cursor_header, sizeof(cursor_header) * sizeof(uint8_t));
  memcpy((uint8_t *) return_data + (sizeof(cursor_header) * sizeof(uint8_t)), (uint8_t *) data + 4, *size - 4);
  free(data);

  *size = (uint32_t) return_size;
  return return_data;
}

void * PeResourceLoader_ProcessIconData(void * data, uint32_t * size) {
  if (!data || !size) {
    free(data);
    if (size) {
      *size = 0;
    }
    return NULL;
  }

  uint8_t icon_header[] = {0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0xa8, 0x08, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00};
  uint64_t return_size = sizeof(icon_header) + *size;
  if (return_size > SIZE_MAX) {
    free(data);
    *size = 0;
    return NULL;
  }

  void * return_data = calloc((size_t) return_size, sizeof(uint8_t));
  if (!return_data) {
    free(data);
    *size = 0;
    return NULL;
  }
  memcpy(return_data, icon_header, sizeof(icon_header) * sizeof(uint8_t));
  memcpy((uint8_t *) return_data + (sizeof(icon_header) * sizeof(uint8_t)), data, *size);
  free(data);

  *size = (uint32_t) return_size;
  return return_data;
}

void * PeResourceLoader_ProcessBitmapData(void * data, uint32_t * size) {
  if (!data || !size || *size < 4) {
    free(data);
    if (size) {
      *size = 0;
    }
    return NULL;
  }

  if (((uint8_t *) data)[0] == 0x42 && ((uint8_t *) data)[1] == 0x4d) {
    // The bmp header exists already
    return data;
  }

  uint8_t bmp_header[] = {0x42, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint64_t return_size = sizeof(bmp_header) + *size;
  if (return_size > UINT32_MAX || return_size > SIZE_MAX) {
    free(data);
    *size = 0;
    return NULL;
  }

  // Fix size in the header
  bmp_header[2] = (uint32_t) return_size & 0xFF;
  bmp_header[3] = ((uint32_t) return_size >> 8) & 0xFF;
  bmp_header[4] = ((uint32_t) return_size >> 16) & 0xFF;
  bmp_header[5] = (uint32_t) return_size >> 24;

  // Set the offset of the pixel data
  uint32_t header_size = ((uint32_t *) data)[0];
  uint64_t data_offset = sizeof(bmp_header) + header_size;
  if (data_offset > UINT32_MAX) {
    free(data);
    *size = 0;
    return NULL;
  }

  // Get the pixel size from the header and adjust the data offset accordingly
  if (header_size == 12) {
    if (*size < 12) {
      free(data);
      *size = 0;
      return NULL;
    }

    // This is an OS/2 header
    uint16_t pixel_size = ((uint16_t *) data)[5];
    switch (pixel_size) {
      case 1:
        data_offset += 2 * 3;
        break;
      case 4:
        data_offset += 16 * 3;
        break;
      case 8:
        data_offset += 256 * 3;
        break;
      case 24:
        break;
      default:
        break;
    }
  } else if (header_size >= 40) {
    if (*size < 36) {
      free(data);
      *size = 0;
      return NULL;
    }
    uint16_t pixel_size = ((uint16_t *) data)[7];
    uint32_t colors_in_palette = ((uint32_t *) data)[8];
    if(colors_in_palette) {
      data_offset += colors_in_palette * 4;
    } else {
      switch (pixel_size) {
        case 1:
          data_offset += 2 * 4;
          break;
        case 4:
          data_offset += 16 * 4;
          break;
        case 8:
          data_offset += 256 * 4;
          break;
        case 24:
          break;
        case 16:
        case 32:
          {
            uint32_t compression_used = ((uint32_t *) data)[4];
            if (compression_used == 3)
              data_offset += 3 * 4;
          }
          break;
        default:
          break;
      }
    }
  }  

  if (data_offset > UINT32_MAX || data_offset > return_size) {
    free(data);
    *size = 0;
    return NULL;
  }

  // Add offset to the header
  bmp_header[10] = (uint32_t) data_offset & 0xFF;
  bmp_header[11] = ((uint32_t) data_offset >> 8) & 0xFF;
  bmp_header[12] = ((uint32_t) data_offset >> 16) & 0xFF;
  bmp_header[13] = (uint32_t) data_offset >> 24;

  void * return_data = calloc(1, (size_t) return_size);
  if (!return_data) {
    free(data);
    *size = 0;
    return NULL;
  }
  memcpy(return_data, bmp_header, sizeof(bmp_header));
  memcpy((uint8_t *) return_data + (sizeof(bmp_header)), data, *size);
  free(data);

  *size = (uint32_t) return_size;
  return return_data;
}

void * PeResourceLoader_ProcessStringData(uint32_t string_id, void * data, uint32_t * size) {
  if (!size || !data || *size == 0) {
    free(data);
    if (size) {
      *size = 0;
    }
    return NULL;
  }

  if ((*size % sizeof(uint16_t)) != 0) {
    free(data);
    *size = 0;
    return NULL;
  }

  uint32_t id = (string_id & 0xFFFFFFFFFFFFFFF0);  // The first id in a list of strings rounds to base 16

  void * string = NULL;
  for(uint32_t i = 0; i < (*size / sizeof(uint16_t)); i++) {
      if (((uint16_t *) data)[i]) {
        if (id == string_id) {
          uint16_t length = ((uint16_t *) data)[i];
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

void * PeResourceLoader_ProcessResourceData(PRL_Type resource_type, void * data, uint32_t * size, uint32_t string_id) {
  switch (resource_type) {
    case PRL_TYPE_STRING:
      data = PeResourceLoader_ProcessStringData(string_id, data, size);
      break;
    case PRL_TYPE_BITMAP:
      data = PeResourceLoader_ProcessBitmapData(data, size);
      break;
    case PRL_TYPE_ICON:
      data = PeResourceLoader_ProcessIconData(data, size);
      break;
    case PRL_TYPE_CURSOR:
      data = PeResourceLoader_ProcessCursorData(data, size);
      break;
    default:
      break;
  }
  return data;
}


void * PeResourceLoader_GetResource(PeResourceLoader * loader, PRL_Type resource_type, uint32_t language_id, uint32_t resource_id, uint32_t * size) {
  if (!loader || !loader->fd) {
    if (size != NULL) {
      *size = 0;
    }
    return NULL;
  }

  if (size != NULL) {
    *size = 0;
  }
  
  uint32_t string_id = 0;
  if(resource_type == PRL_TYPE_STRING && !(resource_id & 0x80000000)) {
    string_id = resource_id;
    resource_id = resource_id / 16 + 1;
  }

  PE_ResourceDataEntry * data_entry = PeResourceLoader_GetDataEntry(loader, language_id, resource_id, resource_type);
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
    data = PeResourceLoader_ProcessResourceData(resource_type, data, size, string_id);
  } else {
    uint32_t temp_size = data_entry->size;
    free(data_entry);
    data = PeResourceLoader_ProcessResourceData(resource_type, data, &temp_size, string_id);
  }

  return data;
}

void * PeResourceLoader_GetNamedResource(PeResourceLoader *loader, PRL_Type resource_type, uint32_t language_id, PRL_ResourceName * resource_name, uint32_t *size) {
  if (!resource_name) {
    if (size) {
      *size = 0;
    }
    return NULL;
  }

  return PeResourceLoader_GetResource(loader, resource_type, language_id, resource_name->name_offset_or_id, size);
}

uint32_t *PeResourceLoader_GetResourceTypes(PeResourceLoader *loader, uint16_t *resource_type_count)
{
  if (!loader || !loader->fd || !resource_type_count) {
    return NULL;
  }

  *resource_type_count = 0;
  uint32_t * resource_types = NULL;
  PRL_ResourceDirectoryEntry * entries = PeResourceLoader_GetDirectoryIdEntries(loader, 0, resource_type_count);
  if (*resource_type_count > 0){
    resource_types = (uint32_t *) calloc(*resource_type_count, sizeof(uint32_t));
    if (!resource_types) {
      free(entries);
      *resource_type_count = 0;
      return NULL;
    }
    for (uint16_t i = 0; i < *resource_type_count; i++) {
      resource_types[i] = entries[i].name_offset_or_id & 0x7FFFFFFF;
    }
  }
  free(entries);
  return resource_types;
}
