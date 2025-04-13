# PE Resource Loader

Allow you to load resources from Windows exe and dll files even outside of Windows. For now it only supports strings.

## Using the PE Resource Loader Library

Here is a basic example of how the PE Resource Loader library can be used in a program to extract a specific string from a DLL file:

```
#include <stdio.h>
#include <stdlib.h>

#include <pe_resource_loader.h>

int main(int argc, char ** argv) {
  // Load your dll or exe file from which you want to extract strings
  PeResourceLoader  * loader = PeResourceLoader_Open("strings.dll");
  if (!loader) {
    printf("PE file failed to load\n");
    return 1;
  }

  // In this example we load string 107 in US English and we don't save the length
  uint8_t * string = PeResourceLoader_GetString(loader, PRL_LANG_EN_US, 107, NULL);
  if (!string) {
    printf("Could not find string 107\n");
    return 2;
  }
  printf("%s\n", string);

  // Don't forget to free strings that are no longer used
  free(string);

  // Always close the loader
  PeResourceLoader_Close(loader);

  return 0; 
}
```

Make sure to link your code to `pe_resource_loader`. The code for the bundled pe_string_loader program contains another more complex example.

## Using PE String Loader Program

The bundled `pe_string_loader` program is mostly there to serve as an example of how the PE Resource Loader library can be used, but it does allow getting strings from binaries and DLLs without any additional code. Here is a basic example:

```
./pe_string_loader my-file.dll
```

It will output a list of string for each included language. If the file contains no strings, nothing will be printed.

## Building

Building the code can be done simply by running the following commands:

```
git clone https://github.com/sharkwouter/pe-resource-loader.git
cd pe-resource-loader
mkdir build
cd build
cmake ..
make
```

Installing can be done with the following command after running the ones above:

```
sudo make install
```

No dependencies are needed other than a C compiler. This code will only work on little endian systems for now.

Building without building the `pe_string_loader` program can be done by running the cmake command the `-DPE_STRING_LOADER=OFF`.
