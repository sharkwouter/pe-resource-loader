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

#define DOS_HEADER_SIZE 64
#define FILE_HEADER_SIZE 20
#define OPTIONAL_HEADER_SIZE 96
#define OPTIONAL_HEADER_64_SIZE 112
#define DATA_DIRECTORY_SIZE 8
#define SECTION_HEADER_SIZE 40
#define NT_SIGNATURE_SIZE 4
#define RESOURCE_DIRECTORY_TABLE_SIZE 16
#define RESOURCE_DIRECTORY_ENTRY_SIZE 8

#define SHORT_NAME_SIZE 8

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
  uint32_t  name_offset_and_id;
  uint32_t  data_or_subdirectory_offset;
} ResourceDirectoryEntry;

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
  fseek(fd, 0, SEEK_END);
  uint32_t file_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  // Get NT header offset from DOS header
  DosHeader * dos_header = (DosHeader *) calloc(1, sizeof(DosHeader));
  fread(dos_header, sizeof(DosHeader), 1, fd);
  assert(dos_header->magic == MZ); // Make sure the magic number in the DOS header is set
  assert(fseek(fd, dos_header->nt_header_offset, SEEK_SET) == 0); // Navigate to the NT header offset
  free(dos_header);

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

  // Read the 
  fseek(fd, resource_offset, SEEK_SET);
  ResourceDirectoryTable * resource_directory_table = (ResourceDirectoryTable *) calloc(1, sizeof(ResourceDirectoryTable));
  fread(resource_directory_table, sizeof(ResourceDirectoryTable), 1, fd);
  
  ResourceDirectoryEntry * name_directory_entries = (ResourceDirectoryEntry *) calloc(resource_directory_table->number_of_name_entries, sizeof(ResourceDirectoryEntry));
  ResourceDirectoryEntry * id_directory_entries = (ResourceDirectoryEntry *) calloc(resource_directory_table->number_of_id_entries, sizeof(ResourceDirectoryEntry));
  fread(name_directory_entries, sizeof(ResourceDirectoryEntry), resource_directory_table->number_of_name_entries, fd);
  fread(id_directory_entries, sizeof(ResourceDirectoryEntry), resource_directory_table->number_of_id_entries, fd);
  int64_t resources_start = ftell(fd);
  printf("Number of name entries: %i\n", resource_directory_table->number_of_name_entries);
  printf("Number of id entries: %i\n", resource_directory_table->number_of_id_entries);
  for(int i = 0; i < resource_directory_table->number_of_name_entries; i++) {
    int is_resource_data_entry_offset = ((name_directory_entries[i].data_or_subdirectory_offset & 0x80000000) == 0);
    uint16_t name_length;
    uint32_t name_offset = (name_directory_entries[i].name_offset_and_id & 0x7FFFFFFF);

    fseek(fd, resource_offset + name_offset, SEEK_SET);
    fread(&name_length, sizeof(uint16_t), 1, fd);
    
    uint16_t * name = (uint16_t *) calloc(name_length, sizeof(uint16_t));
    uint8_t * name_fixed = (uint8_t *) calloc(name_length, sizeof(uint8_t));
    
    // fread(name, sizeof(uint16_t), 1, fd);

    fread(name, sizeof(uint16_t), name_length, fd);
    for(int i = 0; i < name_length; i++) {
      name_fixed[i] = (uint8_t) (name[i] & 0x0000FFFF);
    }

    if (name_length != 0) {
      printf("length %i, name: %s\n", name_length, name_fixed);

      continue;
    }
    printf("Found name: %s\n", name);
    if (is_resource_data_entry_offset) {

    } else {

    }
    free(name);
    free(name_fixed);
  }
  
  fclose(fd);
  free(file_header);

  return 0; 
}
