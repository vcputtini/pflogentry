cmake_minimum_required(VERSION 3.14)
project(pflogentry LANGUAGES CXX VERSION 1.0 DESCRIPTION "pfSense Filter Log Analizer")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

add_definitions("-Wall -Wextra -pedantic")

# These macros make the 'parser' function print the values of the retrieved
# fields to stdout.
#
# Important: Only activate these macros for testing. In production environment
# they must be disabled.

#add_definitions("-DDEBUG_PARSER")


file(WRITE "${CMAKE_SOURCE_DIR}/QtCreatorDeployment.txt" "<deployment/prefix>\n")

add_library(pflogentry SHARED
	pflogentry.h
	pflogentry.cc
)

set_target_properties(pflogentry PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER pflogentry.h)

find_package(tinyxml2 REQUIRED)

target_include_directories(pflogentry PRIVATE .)
set_target_properties(pflogentry PROPERTIES PUBLIC_HEADER pflogentry.h)

target_link_libraries(pflogentry PRIVATE tinyxml2 -lpthread)
target_compile_definitions(pflogentry PRIVATE pflogentry_LIBRARY)

# Uncomment to install
#install(TARGETS pflogentry DESTINATION /lib64)
#install(FILES pflogentry.h DESTINATION /usr/include)
