# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /dados/desenvolvimento/cplusplus/pflogentry

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /dados/desenvolvimento/cplusplus/pflogentry

# Include any dependencies generated for this target.
include CMakeFiles/pflogentry.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/pflogentry.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/pflogentry.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/pflogentry.dir/flags.make

CMakeFiles/pflogentry.dir/pflogentry.cc.o: CMakeFiles/pflogentry.dir/flags.make
CMakeFiles/pflogentry.dir/pflogentry.cc.o: pflogentry.cc
CMakeFiles/pflogentry.dir/pflogentry.cc.o: CMakeFiles/pflogentry.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/dados/desenvolvimento/cplusplus/pflogentry/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/pflogentry.dir/pflogentry.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/pflogentry.dir/pflogentry.cc.o -MF CMakeFiles/pflogentry.dir/pflogentry.cc.o.d -o CMakeFiles/pflogentry.dir/pflogentry.cc.o -c /dados/desenvolvimento/cplusplus/pflogentry/pflogentry.cc

CMakeFiles/pflogentry.dir/pflogentry.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/pflogentry.dir/pflogentry.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /dados/desenvolvimento/cplusplus/pflogentry/pflogentry.cc > CMakeFiles/pflogentry.dir/pflogentry.cc.i

CMakeFiles/pflogentry.dir/pflogentry.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/pflogentry.dir/pflogentry.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /dados/desenvolvimento/cplusplus/pflogentry/pflogentry.cc -o CMakeFiles/pflogentry.dir/pflogentry.cc.s

# Object files for target pflogentry
pflogentry_OBJECTS = \
"CMakeFiles/pflogentry.dir/pflogentry.cc.o"

# External object files for target pflogentry
pflogentry_EXTERNAL_OBJECTS =

libpflogentry.so.1.0: CMakeFiles/pflogentry.dir/pflogentry.cc.o
libpflogentry.so.1.0: CMakeFiles/pflogentry.dir/build.make
libpflogentry.so.1.0: CMakeFiles/pflogentry.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/dados/desenvolvimento/cplusplus/pflogentry/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libpflogentry.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pflogentry.dir/link.txt --verbose=$(VERBOSE)
	$(CMAKE_COMMAND) -E cmake_symlink_library libpflogentry.so.1.0 libpflogentry.so.1 libpflogentry.so

libpflogentry.so.1: libpflogentry.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate libpflogentry.so.1

libpflogentry.so: libpflogentry.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate libpflogentry.so

# Rule to build all files generated by this target.
CMakeFiles/pflogentry.dir/build: libpflogentry.so
.PHONY : CMakeFiles/pflogentry.dir/build

CMakeFiles/pflogentry.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/pflogentry.dir/cmake_clean.cmake
.PHONY : CMakeFiles/pflogentry.dir/clean

CMakeFiles/pflogentry.dir/depend:
	cd /dados/desenvolvimento/cplusplus/pflogentry && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /dados/desenvolvimento/cplusplus/pflogentry /dados/desenvolvimento/cplusplus/pflogentry /dados/desenvolvimento/cplusplus/pflogentry /dados/desenvolvimento/cplusplus/pflogentry /dados/desenvolvimento/cplusplus/pflogentry/CMakeFiles/pflogentry.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/pflogentry.dir/depend

