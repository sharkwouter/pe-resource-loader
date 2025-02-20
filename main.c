#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <locale.h>
#include <wchar.h>

#define MZ 0x5A4D

#define AMD64 0x8664
#define i386 0x14c

#define PE32 0x10B
#define PE32PLUS 0x20B

#define EXPECTED_NT_SIGNATURE "PE"

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

// Resource name types
#define RT_NAME_TEXT "TEXT"

// Valid sizes for structs used
#define DOS_HEADER_SIZE 64
#define FILE_HEADER_SIZE 20
#define OPTIONAL_HEADER_SIZE 96
#define OPTIONAL_HEADER_64_SIZE 112
#define DATA_DIRECTORY_SIZE 8
#define SECTION_HEADER_SIZE 40
#define NT_SIGNATURE_SIZE 4
#define RESOURCE_DIRECTORY_TABLE_SIZE 16
#define RESOURCE_DIRECTORY_ENTRY_SIZE 8

typedef struct __attribute__((packed)) {
  uint16_t  magic;
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

  uint8_t * name = (uint8_t *) calloc(name_length, sizeof(uint8_t));
  if (NULL == name) {
    free(name_wide);
    return NULL;
  }

  for(int i = 0; i < name_length; i++) {
    name[i] = (uint8_t) name_wide[i];
  }
  if (length != NULL) {
    *length = name_length;
  }
  free(name_wide);

  return name;
}

void read_data(FILE * fd, uint32_t resource_offset, uint32_t data_offset, uint32_t size) {
  uint32_t offset = resource_offset + data_offset;

  uint8_t * data = (uint8_t *) calloc(sizeof(uint8_t), size);
  fseek(fd, offset, SEEK_SET);
  fread(data, sizeof(uint8_t), size, fd);

  if (data[1] == '\0') {
    uint8_t * string = (uint8_t *) calloc(sizeof(uint8_t), size / 2);
    size_t current_char = 0;
    for (int i = 0; i < size; i+=2) {
      string[current_char] = data[i];
      current_char++;
    }
    // printf("Data found: %s\n", string);
  } else {
    // printf("Data found: %s\n", data);
  }

  free(data);
}

void read_directory_entry(FILE * fd, uint32_t resource_offset, uint32_t entry_offset) {
  uint32_t offset = resource_offset + entry_offset;

  ResourceDataEntry resource_directory_entry;
  fseek(fd, offset, SEEK_SET);
  fread(&resource_directory_entry, sizeof(ResourceDataEntry), 1, fd);

  // printf("Offset is: %i\n", resource_directory_entry.offset_to_data);
  read_data(fd, resource_offset, resource_directory_entry.offset_to_data, resource_directory_entry.size);
}

void read_directory_table(FILE * fd, uint32_t resource_offset, uint32_t directory_offset) {
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
      read_directory_entry(fd, resource_offset, directory_entries[i].data_or_subdirectory_offset);
    } else {
      if (is_named) {
        uint8_t * name = read_directory_name(fd, resource_offset, directory_entries[i].name_offset_or_id, NULL);
        printf("Found data with name: %s\n", name);
        // if (name != NULL && strcmp(name, "TEXT") == 0) {
        //   printf("Found data with name: %s\n", name);
        free(name);
        //   // exit(0);
        // }
      } else {
        switch (directory_entries[i].name_offset_or_id) {
          case RT_CURSOR:
            printf("Found cursor table\n");
            break;
          case RT_BITMAP:
            printf("Found bitmap table\n");
            break;
          case RT_ICON:
            printf("Found icon table\n");
            break;
          case RT_MENU:
            printf("Found menu table\n");
            break;
          case RT_DIALOG:
            printf("Found dialog table\n");
            break;
          case RT_STRING:
            printf("Found string table\n");
            break;
          case RT_FONTDIR:
            printf("Found font table\n");
            break;
          case RT_FONT:
            printf("Found font\n");
            break;
          case RT_ACCELERATOR:
            printf("Found accelerator table\n");
            break;
          case RT_RCDATA:
            printf("Found rcdata table\n");
            break;
          case RT_MESSAGETABLE:
            printf("Found message table\n");
            break;
          case RT_VERSION:
            printf("Found version table\n");
            break;
          case RT_DLGINCLUDE:
            printf("Found dlginclude table\n");
            break;
          case RT_PLUGPLAY:
            printf("Found plugplay table\n");
            break;
          case RT_VXD:
            printf("Found vxd table\n");
            break;
          case RT_ANICURSOR:
            printf("Found anicursor table\n");
            break;
          case RT_ANIICON:
            printf("Found aniicon table\n");
            break;
          case RT_HTML:
            printf("Found html table\n");
            break;
          case RT_MANIFEST:
            printf("Found manifest table\n");
            break;
          default:
            printf("Found unsupported table %i\n", directory_entries[i].name_offset_or_id);
            break;
        }
      }
      // read_directory_table(fd, resource_offset, directory_entries[i].data_or_subdirectory_offset);
    }
  }
}

int main(int argc, char ** argv) {
  // Make sure the above structs are the same size as they are on 
  assert(sizeof(DosHeader) == DOS_HEADER_SIZE);
  assert(sizeof(FileHeader) == FILE_HEADER_SIZE);
  assert(sizeof(OptionalHeader) == OPTIONAL_HEADER_SIZE);
  assert(sizeof(OptionalHeader64) == OPTIONAL_HEADER_64_SIZE);
  assert(sizeof(DataDirectory) == DATA_DIRECTORY_SIZE);
  assert(sizeof(SectionHeader) == SECTION_HEADER_SIZE);
  assert(sizeof(ResourceDirectoryTable) == RESOURCE_DIRECTORY_TABLE_SIZE);
  assert(sizeof(ResourceDirectoryEntry) == RESOURCE_DIRECTORY_ENTRY_SIZE);

  if (argc != 2) {
    printf("No file was defined\n");
    return 1;
  }

  printf("Opening file %s\n", argv[1]);
  FILE * fd = fopen(argv[1], "rb");
  if (fd == NULL) {
    printf("Could not read file %s\n", argv[1]);
    return 2;
  }

  // Get NT header offset from DOS header
  DosHeader dos_header;
  fread(&dos_header, sizeof(DosHeader), 1, fd);
  assert(dos_header.magic == MZ); // Make sure the magic number in the DOS header is set
  assert(fseek(fd, dos_header.nt_header_offset, SEEK_SET) == 0); // Navigate to the NT header offset

  // Make sure the NT signature is valid
  uint8_t * nt_signature = (uint8_t *) calloc(1, NT_SIGNATURE_SIZE);
  fread(nt_signature, 1, NT_SIGNATURE_SIZE, fd);
  assert(strcmp(nt_signature, EXPECTED_NT_SIGNATURE) == 0); // Make sure this is the NT header
  free(nt_signature);

  // Get the machine type from the file header
  FileHeader * file_header = (FileHeader *) calloc(1, sizeof(FileHeader));
  fread(file_header, sizeof(FileHeader), 1, fd);

  DataDirectory * data_directories = NULL;
  uint16_t section_alignment = 0;
  uint16_t file_alignment = 0;
  uint32_t number_of_data_directories = 0;
  switch (file_header->machine) {
    case i386:
      {
        // Get the number of data directories
        OptionalHeader optional_header;
        fread(&optional_header, sizeof(OptionalHeader), 1, fd);
        assert(optional_header.magic == PE32); // If this fails we're either dealing with ROM or invalid data
        //printf("NT Magic: %s\n", optional_header.magic);
        section_alignment = optional_header.section_alignment;
        number_of_data_directories = optional_header.number_of_data_directories;

        // Get the data directory list to get the resource directory location
        data_directories = (DataDirectory *) calloc(optional_header.number_of_data_directories, sizeof(DataDirectory));
        fread(data_directories, sizeof(DataDirectory), optional_header.number_of_data_directories, fd);
      }
      break;
    case AMD64:
      {
        // Get the number of data directories
        OptionalHeader64 optional_header;
        fread(&optional_header, sizeof(OptionalHeader64), 1, fd);
        assert(optional_header.magic == PE32PLUS); // If this fails we're either dealing with ROM or invalid data
        section_alignment = optional_header.section_alignment;
        number_of_data_directories = optional_header.number_of_data_directories;
        printf("Section alignment and file alignment: %i, %i\n", section_alignment, optional_header.file_alignment);
  
        // Get the data directory list to get the resource directory location
        data_directories = (DataDirectory *) calloc(optional_header.number_of_data_directories, sizeof(DataDirectory));
        fread(data_directories, sizeof(DataDirectory), optional_header.number_of_data_directories, fd);
      }
      break;
    default:
      printf("Unsupported machine type\n");
      return 3;
      break;
  }
 
  printf("Number of directories:%i\n", number_of_data_directories);
  if (number_of_data_directories > DIRECTORY_ENTRY_RESOURCE && data_directories[DIRECTORY_ENTRY_RESOURCE].offset == 0 || data_directories[DIRECTORY_ENTRY_RESOURCE].size == 0) {
    printf("No resources found in file %s\n", argv[1]);
    return 4;
  }
  free(data_directories);

  // Read the section headers
  uint32_t resource_offset;
  SectionHeader * section_headers = (SectionHeader *) calloc(file_header->number_of_sections, sizeof(SectionHeader));
  fread(section_headers, sizeof(SectionHeader), file_header->number_of_sections, fd);
  for(int i = 0; i < file_header->number_of_sections; i++) {
    if (strcmp(".rsrc", section_headers[i].name) == 0) {
      printf("Found .rsrc\n");
      resource_offset = section_headers[i].address;
    }
  }

  read_directory_table(fd, resource_offset, 0);
  fclose(fd);
  free(file_header);

  return 0; 
}
