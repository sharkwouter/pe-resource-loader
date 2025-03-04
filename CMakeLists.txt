cmake_minimum_required(VERSION 3.10)

project(pe_resource_loader)

add_library(pe_resource_loader src/pe_resource_loader.c)
target_include_directories(pe_resource_loader PRIVATE
  include/
)

option(BUILD_STRING_LOADER_PROGRAM "If the string loader program should be build as well" OFF)

if(BUILD_STRING_LOADER_PROGRAM)
  add_executable(string_loader string_loader/main.c)
  target_include_directories(string_loader PRIVATE
    include/
  )
  target_link_libraries(string_loader pe_resource_loader)
endif(BUILD_STRING_LOADER_PROGRAM)