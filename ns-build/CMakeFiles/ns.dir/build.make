# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.0

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
CMAKE_SOURCE_DIR = /home/ma/ns-allinone-2.29/ns-2.29/ns

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ma/ns-allinone-2.29/ns-2.29/ns-build

# Include any dependencies generated for this target.
include CMakeFiles/ns.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ns.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ns.dir/flags.make

CMakeFiles/ns.dir/main.cpp.o: CMakeFiles/ns.dir/flags.make
CMakeFiles/ns.dir/main.cpp.o: /home/ma/ns-allinone-2.29/ns-2.29/ns/main.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ma/ns-allinone-2.29/ns-2.29/ns-build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/ns.dir/main.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/ns.dir/main.cpp.o -c /home/ma/ns-allinone-2.29/ns-2.29/ns/main.cpp

CMakeFiles/ns.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ns.dir/main.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/ma/ns-allinone-2.29/ns-2.29/ns/main.cpp > CMakeFiles/ns.dir/main.cpp.i

CMakeFiles/ns.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ns.dir/main.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/ma/ns-allinone-2.29/ns-2.29/ns/main.cpp -o CMakeFiles/ns.dir/main.cpp.s

CMakeFiles/ns.dir/main.cpp.o.requires:
.PHONY : CMakeFiles/ns.dir/main.cpp.o.requires

CMakeFiles/ns.dir/main.cpp.o.provides: CMakeFiles/ns.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/ns.dir/build.make CMakeFiles/ns.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/ns.dir/main.cpp.o.provides

CMakeFiles/ns.dir/main.cpp.o.provides.build: CMakeFiles/ns.dir/main.cpp.o

# Object files for target ns
ns_OBJECTS = \
"CMakeFiles/ns.dir/main.cpp.o"

# External object files for target ns
ns_EXTERNAL_OBJECTS =

ns: CMakeFiles/ns.dir/main.cpp.o
ns: CMakeFiles/ns.dir/build.make
ns: CMakeFiles/ns.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable ns"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ns.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ns.dir/build: ns
.PHONY : CMakeFiles/ns.dir/build

CMakeFiles/ns.dir/requires: CMakeFiles/ns.dir/main.cpp.o.requires
.PHONY : CMakeFiles/ns.dir/requires

CMakeFiles/ns.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ns.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ns.dir/clean

CMakeFiles/ns.dir/depend:
	cd /home/ma/ns-allinone-2.29/ns-2.29/ns-build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ma/ns-allinone-2.29/ns-2.29/ns /home/ma/ns-allinone-2.29/ns-2.29/ns /home/ma/ns-allinone-2.29/ns-2.29/ns-build /home/ma/ns-allinone-2.29/ns-2.29/ns-build /home/ma/ns-allinone-2.29/ns-2.29/ns-build/CMakeFiles/ns.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ns.dir/depend
