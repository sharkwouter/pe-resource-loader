cmake_minimum_required(VERSION 3.10)

project(pe_resource_loader)

add_library(pe_resource_loader src/pe_resource_loader.c src/tm_unicode.h)
target_include_directories(pe_resource_loader PRIVATE
  include/
)

option(PE_STRING_LOADER "If the pe_string_loader program should be build as well" ON)
if(PE_STRING_LOADER)
  add_executable(pe_string_loader pe_string_loader/main.c)
  target_include_directories(pe_string_loader PRIVATE
    include/
  )
  target_link_libraries(pe_string_loader pe_resource_loader)
endif(PE_STRING_LOADER)

if (NOT WIN32)
  install(TARGETS pe_resource_loader DESTINATION lib)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pe_resource_loader.h DESTINATION include/)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt DESTINATION share/licenses/pe_resource_loader/)
  if(PE_STRING_LOADER)
    install(TARGETS pe_string_loader DESTINATION bin)
  endif(PE_STRING_LOADER)
endif(NOT WIN32)