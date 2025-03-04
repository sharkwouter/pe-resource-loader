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

if (NOT WIN32)
  install(TARGETS pe_resource_loader DESTINATION lib)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pe_resource_loader.h DESTINATION include/)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt DESTINATION share/licenses/pe_resource_loader/)
  if(BUILD_STRING_LOADER_PROGRAM)
    install(TARGETS string_loader DESTINATION bin)
  endif(BUILD_STRING_LOADER_PROGRAM)
endif(NOT WIN32)