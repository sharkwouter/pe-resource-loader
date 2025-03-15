#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <pe_resource_loader.h>

// These are used in open
#define MZ 0x5A4D

#define AMD64 0x8664
#define i386 0x14c

#define PE32 0x10B
#define PE32PLUS 0x20B
// End these are used in open

// These could be used in open
#define EXPECTED_NT_SIGNATURE "PE"
#define NT_SIGNATURE_SIZE 4
// End these could be used in open

#define DIRECTORY_ENTRY_RESOURCE 2

#define SHORT_NAME_SIZE 8

// Resource ID types
#define RT_CURSOR 1
#define RT_BITMAP 2
#define RT_ICON 3
#define RT_MENU 4
#define RT_DIALOG 5
#define RT_STRING 6
#define RT_FONTDIR 7
#define RT_FONT 8
#define RT_ACCELERATOR 9
#define RT_RCDATA 10
#define RT_MESSAGETABLE 11
#define RT_VERSION 16
#define RT_DLGINCLUDE 17
#define RT_PLUGPLAY 19
#define RT_VXD 20
#define RT_ANICURSOR 21
#define RT_ANIICON 22
#define RT_HTML 23
#define RT_MANIFEST 24

// Language codes
#define LANGUAGE_ENGLISH_US 1033

// Resource name types
#define RT_NAME_TEXT "TEXT"

// Valid sizes for structs used
#define DOS_HEADER_SIZE 64
#define FILE_HEADER_SIZE 20
#define OPTIONAL_HEADER_SIZE 96
#define OPTIONAL_HEADER_64_SIZE 112
#define DATA_DIRECTORY_SIZE 8
#define SECTION_HEADER_SIZE 40
#define RESOURCE_DIRECTORY_TABLE_SIZE 16
#define RESOURCE_DIRECTORY_ENTRY_SIZE 8

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

uint32_t section_virtual_address = 0;
uint32_t section_address = 0;

uint32_t wide_string_length_with_size(uint16_t * str, uint32_t size) {
  size_t full_length = size/sizeof(uint16_t);
  for (int i = 0; i < full_length; i++) {
    if (str[i] == '\0') {
      return i;
    }
  }
  return full_length;
}

uint32_t wide_string_length(uint16_t * str) {
  return wide_string_length_with_size(str, sizeof(str));
}

uint8_t * wide_string_to_utf8(uint16_t * str, uint16_t length) {
  uint8_t * output = (uint8_t *) calloc(length + 1, sizeof(uint8_t));

  for (int i = 0; i < length; i++) {
    if (str[i] < 128) {
      output[i] = (uint8_t) str[i];
    } else {
      output[i] = '?';  // Not great, but since the game is in english, this should not be used a lot
    }
  }

  output[length] = '\0';
  return output;
}

uint8_t * read_directory_name(FILE * fd, uint32_t resource_offset, uint32_t name_offset, uint16_t * length) {
  uint16_t name_length;
  uint32_t offset = resource_offset + (name_offset & 0x7FFFFFFF);
  fseek(fd, offset, SEEK_SET);
  fread(&name_length, sizeof(uint16_t), 1, fd);
  if (name_length < 1) {
    return NULL;
  }

  uint16_t * name_wide = (uint16_t *) calloc(name_length, sizeof(uint16_t));
  if (NULL == name_wide) {
    return NULL;
  }
  fread(name_wide, sizeof(uint16_t), name_length, fd);

  uint8_t * name = wide_string_to_utf8(name_wide, name_length);
  free(name_wide);

  return name;
}

void read_data_entry(FILE * fd, uint32_t resource_offset, uint32_t entry_offset, uint32_t id) {
  uint32_t offset = resource_offset + (entry_offset & 0x7FFFFFFF);

  ResourceDataEntry resource_directory_entry;
  fseek(fd, offset, SEEK_SET);
  fread(&resource_directory_entry, sizeof(ResourceDataEntry), 1, fd);
  if (resource_directory_entry.code_page > 0 || resource_directory_entry.reserved > 0) {
    printf("Invalid data entry found. Data entry read: offset_to_data=%i, size=%i, code_page=%i, reserved=%i\n", resource_directory_entry.offset_to_data, resource_directory_entry.size, resource_directory_entry.code_page, resource_directory_entry.reserved);
    exit(15);
  }
  uint32_t data_length = resource_directory_entry.size / sizeof(uint16_t);
  uint16_t * data = (uint16_t *) calloc(data_length, sizeof(uint16_t));
  uint16_t first_value;
  uint32_t file_offset = (resource_directory_entry.offset_to_data & 0x7FFFFFFF) - section_virtual_address  + section_address;

  fseek(fd, file_offset, SEEK_SET);
  fread(data, sizeof(uint16_t), data_length, fd);
  id = (id - 1) * 16;
  for(int i = 0; i < data_length; i++) {
      if (data[i]) {
        printf("%i: ", id);
        for(int j = 0; j < data[i]; j++) {
          printf("%c", (uint8_t) data[i + 1 + j]);
        }
        printf("\n");
        i += data[i];
      }
      id += 1;
  }
}

void read_language_directory(FILE * fd, uint32_t resource_offset, uint32_t directory_offset, uint32_t id) {
  uint32_t offset = resource_offset + (directory_offset & 0x7FFFFFFF);

  ResourceDirectoryTable resource_directory_table;
  fseek(fd, offset, SEEK_SET);
  fread(&resource_directory_table, sizeof(ResourceDirectoryTable), 1, fd);
  uint16_t entry_count = resource_directory_table.number_of_name_entries + resource_directory_table.number_of_id_entries;

  ResourceDirectoryEntry * directory_entries = (ResourceDirectoryEntry *) calloc(entry_count, sizeof(ResourceDirectoryEntry));
  fread(directory_entries, sizeof(ResourceDirectoryEntry), entry_count, fd);
  for (int i = 0; i < entry_count; i++) {
    int is_data = ((directory_entries[i].data_or_subdirectory_offset & 0x80000000) == 0);

    if (is_data) {
      if (directory_entries[i].name_offset_or_id == LANGUAGE_ENGLISH_US) {
        // printf("String is in American English\n");
      } else {
        // printf("String is in language with id: %i\n", directory_entries[i].name_offset_or_id);
      }
      read_data_entry(fd, resource_offset, directory_entries[i].data_or_subdirectory_offset, id);
    } else {
      printf("Error: expected pointer to data in language entry\n");
      exit(15);
    }
  }
}

void read_string_directory(FILE * fd, uint32_t resource_offset, uint32_t directory_offset) {
  uint32_t offset = resource_offset + (directory_offset & 0x7FFFFFFF);

  ResourceDirectoryTable resource_directory_table;
  fseek(fd, offset, SEEK_SET);
  fread(&resource_directory_table, sizeof(ResourceDirectoryTable), 1, fd);
  uint16_t entry_count = resource_directory_table.number_of_name_entries + resource_directory_table.number_of_id_entries;

  ResourceDirectoryEntry * directory_entries = (ResourceDirectoryEntry *) calloc(entry_count, sizeof(ResourceDirectoryEntry));
  fread(directory_entries, sizeof(ResourceDirectoryEntry), entry_count, fd);
  for (int i = 0; i < entry_count; i++) {
    int is_data = ((directory_entries[i].data_or_subdirectory_offset & 0x80000000) == 0);
    int is_named = ((directory_entries[i].name_offset_or_id & 0x80000000) > 0);

    if (is_data) {
      printf("Found unexpected data in top level string directory\n");
      return;
    } else {
      if (is_named) {
        printf("Name entry found for some reason\n");
      } else {
        printf("Found type id: %i\n", directory_entries[i].name_offset_or_id);
        read_language_directory(fd, resource_offset, directory_entries[i].data_or_subdirectory_offset, directory_entries[i].name_offset_or_id & 0x7FFFFFFF);
      }
    }
  }
}

void read_type_directory(FILE * fd, uint32_t resource_offset, uint32_t directory_offset) {
  uint32_t offset = resource_offset + (directory_offset & 0x7FFFFFFF);

  ResourceDirectoryTable resource_directory_table;
  fseek(fd, offset, SEEK_SET);
  fread(&resource_directory_table, sizeof(ResourceDirectoryTable), 1, fd);
  uint16_t entry_count = resource_directory_table.number_of_name_entries + resource_directory_table.number_of_id_entries;

  ResourceDirectoryEntry * directory_entries = (ResourceDirectoryEntry *) calloc(entry_count, sizeof(ResourceDirectoryEntry));
  fread(directory_entries, sizeof(ResourceDirectoryEntry), entry_count, fd);
  for (int i = 0; i < entry_count; i++) {
    int is_data = ((directory_entries[i].data_or_subdirectory_offset & 0x80000000) == 0);
    int is_named = ((directory_entries[i].name_offset_or_id & 0x80000000) > 0);

    if (is_data) {
      printf("Found data at top level for some reason\n");
      return;
    } else {
      if (is_named) {
        uint8_t * name = read_directory_name(fd, resource_offset, directory_entries[i].name_offset_or_id, NULL);
        // printf("Found data with name: %s\n", name);
        free(name);
      } else {
        switch (directory_entries[i].name_offset_or_id) {
          case RT_CURSOR:
            // printf("Found cursor table\n");
            break;
          case RT_BITMAP:
            // printf("Found bitmap table\n");
            break;
          case RT_ICON:
            // printf("Found icon table\n");
            break;
          case RT_MENU:
            // printf("Found menu table\n");
            break;
          case RT_DIALOG:
            // printf("Found dialog table\n");
            break;
          case RT_STRING:
            // printf("Found string table\n");
            read_string_directory(fd, resource_offset, directory_entries[i].data_or_subdirectory_offset);
            break;
          case RT_FONTDIR:
            // printf("Found font table\n");
            break;
          case RT_FONT:
            // printf("Found font\n");
            break;
          case RT_ACCELERATOR:
            // printf("Found accelerator table\n");
            break;
          case RT_RCDATA:
            // printf("Found rcdata table\n");
            break;
          case RT_MESSAGETABLE:
            // printf("Found message table\n");
            break;
          case RT_VERSION:
            // printf("Found version table\n");
            break;
          case RT_DLGINCLUDE:
            // printf("Found dlginclude table\n");
            break;
          case RT_PLUGPLAY:
            // printf("Found plugplay table\n");
            break;
          case RT_VXD:
            // printf("Found vxd table\n");
            break;
          case RT_ANICURSOR:
            // printf("Found anicursor table\n");
            break;
          case RT_ANIICON:
            // printf("Found aniicon table\n");
            break;
          case RT_HTML:
            // printf("Found html table\n");
            break;
          case RT_MANIFEST:
            // printf("Found manifest table\n");
            break;
          default:
            // printf("Found unsupported table %i\n", directory_entries[i].name_offset_or_id);
            break;
        }
      }
    }
  }
}

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
  // uint16_t language_count = 0;
  // uint32_t * languages = PeResourceLoader_GetLanguageIds(loader, &language_count);
  // for (uint16_t i = 0; i < language_count; i++) {
  //   printf("Found language with id %u\n", languages[i]);
  // }
  // free(languages);
  // return 0;
  uint16_t length = 0;
  uint8_t * stgring = PeResourceLoader_GetString(loader, 1033, 107, &length);
  printf("%s\n", stgring);

  // section_address = loader->resource_offset;
  // section_virtual_address = loader->resource_virtual_address;

  // read_type_directory(loader->fd, loader->resource_offset, 0);

  PeResourceLoader_Close(loader);

  return 0; 
}
