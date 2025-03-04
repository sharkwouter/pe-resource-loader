#include <stdint.h>
#include <stdio.h>

typedef struct {
  FILE *  fd;
  uint32_t resource_virtual_address;
  uint32_t resource_offset;
} PeResourceLoader;

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

PeResourceLoader * PeResourceLoader_Open(const char * file_path);
PeResourceLoader * PeResourceLoader_Close(PeResourceLoader * loader);