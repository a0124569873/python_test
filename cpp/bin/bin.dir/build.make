# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/Desktop/cpp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/Desktop/cpp

# Include any dependencies generated for this target.
include CMakeFiles/../bin/bin.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/../bin/bin.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/../bin/bin.dir/flags.make

CMakeFiles/../bin/bin.dir/src/a.o: CMakeFiles/../bin/bin.dir/flags.make
CMakeFiles/../bin/bin.dir/src/a.o: src/a.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/Desktop/cpp/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/../bin/bin.dir/src/a.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/../bin/bin.dir/src/a.o   -c /root/Desktop/cpp/src/a.c

CMakeFiles/../bin/bin.dir/src/a.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/../bin/bin.dir/src/a.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/Desktop/cpp/src/a.c > CMakeFiles/../bin/bin.dir/src/a.i

CMakeFiles/../bin/bin.dir/src/a.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/../bin/bin.dir/src/a.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/Desktop/cpp/src/a.c -o CMakeFiles/../bin/bin.dir/src/a.s

CMakeFiles/../bin/bin.dir/src/a.o.requires:

.PHONY : CMakeFiles/../bin/bin.dir/src/a.o.requires

CMakeFiles/../bin/bin.dir/src/a.o.provides: CMakeFiles/../bin/bin.dir/src/a.o.requires
	$(MAKE) -f CMakeFiles/../bin/bin.dir/build.make CMakeFiles/../bin/bin.dir/src/a.o.provides.build
.PHONY : CMakeFiles/../bin/bin.dir/src/a.o.provides

CMakeFiles/../bin/bin.dir/src/a.o.provides.build: CMakeFiles/../bin/bin.dir/src/a.o


CMakeFiles/../bin/bin.dir/src/main.o: CMakeFiles/../bin/bin.dir/flags.make
CMakeFiles/../bin/bin.dir/src/main.o: src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/Desktop/cpp/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/../bin/bin.dir/src/main.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/../bin/bin.dir/src/main.o   -c /root/Desktop/cpp/src/main.c

CMakeFiles/../bin/bin.dir/src/main.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/../bin/bin.dir/src/main.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/Desktop/cpp/src/main.c > CMakeFiles/../bin/bin.dir/src/main.i

CMakeFiles/../bin/bin.dir/src/main.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/../bin/bin.dir/src/main.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/Desktop/cpp/src/main.c -o CMakeFiles/../bin/bin.dir/src/main.s

CMakeFiles/../bin/bin.dir/src/main.o.requires:

.PHONY : CMakeFiles/../bin/bin.dir/src/main.o.requires

CMakeFiles/../bin/bin.dir/src/main.o.provides: CMakeFiles/../bin/bin.dir/src/main.o.requires
	$(MAKE) -f CMakeFiles/../bin/bin.dir/build.make CMakeFiles/../bin/bin.dir/src/main.o.provides.build
.PHONY : CMakeFiles/../bin/bin.dir/src/main.o.provides

CMakeFiles/../bin/bin.dir/src/main.o.provides.build: CMakeFiles/../bin/bin.dir/src/main.o


# Object files for target ../bin/bin
__/bin/bin_OBJECTS = \
"CMakeFiles/../bin/bin.dir/src/a.o" \
"CMakeFiles/../bin/bin.dir/src/main.o"

# External object files for target ../bin/bin
__/bin/bin_EXTERNAL_OBJECTS =

../bin/bin: CMakeFiles/../bin/bin.dir/src/a.o
../bin/bin: CMakeFiles/../bin/bin.dir/src/main.o
../bin/bin: CMakeFiles/../bin/bin.dir/build.make
../bin/bin: CMakeFiles/../bin/bin.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/Desktop/cpp/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable ../bin/bin"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/../bin/bin.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/../bin/bin.dir/build: ../bin/bin

.PHONY : CMakeFiles/../bin/bin.dir/build

CMakeFiles/../bin/bin.dir/requires: CMakeFiles/../bin/bin.dir/src/a.o.requires
CMakeFiles/../bin/bin.dir/requires: CMakeFiles/../bin/bin.dir/src/main.o.requires

.PHONY : CMakeFiles/../bin/bin.dir/requires

CMakeFiles/../bin/bin.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/../bin/bin.dir/cmake_clean.cmake
.PHONY : CMakeFiles/../bin/bin.dir/clean

CMakeFiles/../bin/bin.dir/depend:
	cd /root/Desktop/cpp && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/Desktop/cpp /root/Desktop/cpp /root/Desktop/cpp /root/Desktop/cpp /root/Desktop/cpp/bin/bin.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/../bin/bin.dir/depend

