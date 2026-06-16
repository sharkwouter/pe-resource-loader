#include "pe_resource_loader.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void * PeResourceLoader_ProcessBitmapData(void * data, uint32_t * size);

static int write_file(const char * path, const uint8_t * data, size_t size) {
  FILE * fd = fopen(path, "wb");
  if (!fd) {
    return 0;
  }

  int ok = fwrite(data, 1, size, fd) == size;
  fclose(fd);
  return ok;
}

static int test_truncated_nt_offset(void) {
  char path[] = "/tmp/prl-test-truncated-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) {
    return 0;
  }
  close(fd);

  uint8_t data[64] = {0};
  data[0] = 'M';
  data[1] = 'Z';
  int32_t nt_offset = 0x80;
  memcpy(&data[0x3c], &nt_offset, sizeof(nt_offset));

  if (!write_file(path, data, sizeof(data))) {
    unlink(path);
    return 0;
  }

  PeResourceLoader * loader = PeResourceLoader_Open(path);
  unlink(path);
  if (loader != NULL) {
    PeResourceLoader_Close(loader);
    return 0;
  }

  return 1;
}

static void make_base_pe(uint8_t * data, size_t size, const uint8_t section_name[8]) {
  memset(data, 0, size);
  data[0] = 'M';
  data[1] = 'Z';

  int32_t nt_offset = 0x80;
  memcpy(&data[0x3c], &nt_offset, sizeof(nt_offset));

  data[0x80] = 'P';
  data[0x81] = 'E';
  data[0x82] = 0;
  data[0x83] = 0;

  uint16_t machine = 0x14c;
  uint16_t sections = 1;
  memcpy(&data[0x84], &machine, sizeof(machine));
  memcpy(&data[0x86], &sections, sizeof(sections));

  uint16_t magic = 0x10b;
  memcpy(&data[0x98], &magic, sizeof(magic));

  memcpy(&data[0xf8], section_name, 8);
  uint32_t virtual_size = 0x20;
  uint32_t virtual_address = 0x1000;
  uint32_t raw_size = 0x20;
  uint32_t raw_address = 0x180;
  memcpy(&data[0x100], &virtual_size, sizeof(virtual_size));
  memcpy(&data[0x104], &virtual_address, sizeof(virtual_address));
  memcpy(&data[0x108], &raw_size, sizeof(raw_size));
  memcpy(&data[0x10c], &raw_address, sizeof(raw_address));
}

static int test_invalid_nt_signature(void) {
  char path[] = "/tmp/prl-test-signature-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) {
    return 0;
  }
  close(fd);

  uint8_t data[512] = {0};
  static const uint8_t section_name[8] = {'.', 'r', 's', 'r', 'c', 0, 0, 0};
  make_base_pe(data, sizeof(data), section_name);
  data[0x82] = 'A';
  data[0x83] = 'A';

  if (!write_file(path, data, sizeof(data))) {
    unlink(path);
    return 0;
  }

  PeResourceLoader * loader = PeResourceLoader_Open(path);
  unlink(path);
  if (loader != NULL) {
    PeResourceLoader_Close(loader);
    return 0;
  }

  return 1;
}

static int test_section_name_exact_match(void) {
  char path[] = "/tmp/prl-test-rsrc-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) {
    return 0;
  }
  close(fd);

  uint8_t data[512] = {0};
  static const uint8_t section_name[8] = {'.', 'r', 's', 'r', 'c', 0, 0, 0};
  make_base_pe(data, sizeof(data), section_name);

  if (!write_file(path, data, sizeof(data))) {
    unlink(path);
    return 0;
  }

  PeResourceLoader * loader = PeResourceLoader_Open(path);
  unlink(path);
  if (loader == NULL) {
    return 0;
  }

  PeResourceLoader_Close(loader);
  return 1;
}

static int test_bitmap_header_detection(void) {
  uint32_t size = 14;
  uint8_t * data = (uint8_t *) calloc(size, 1);
  if (!data) {
    return 0;
  }

  data[0] = 0x42;
  data[1] = 0x4d;

  void * result = PeResourceLoader_ProcessBitmapData(data, &size);
  if (result != data || size != 14) {
    free(result);
    return 0;
  }

  free(result);
  return 1;
}

static int test_bitmap_short_data_rejected(void) {
  uint32_t size = 2;
  uint8_t * data = (uint8_t *) calloc(size, 1);
  if (!data) {
    return 0;
  }

  void * result = PeResourceLoader_ProcessBitmapData(data, &size);
  if (result != NULL || size != 0) {
    free(result);
    return 0;
  }

  return 1;
}

int main(void) {
  if (!test_truncated_nt_offset()) {
    fprintf(stderr, "test_truncated_nt_offset failed\n");
    return 1;
  }

  if (!test_invalid_nt_signature()) {
    fprintf(stderr, "test_invalid_nt_signature failed\n");
    return 1;
  }

  if (!test_section_name_exact_match()) {
    fprintf(stderr, "test_section_name_exact_match failed\n");
    return 1;
  }

  if (!test_bitmap_header_detection()) {
    fprintf(stderr, "test_bitmap_header_detection failed\n");
    return 1;
  }

  if (!test_bitmap_short_data_rejected()) {
    fprintf(stderr, "test_bitmap_short_data_rejected failed\n");
    return 1;
  }

  return 0;
}
