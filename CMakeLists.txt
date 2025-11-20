cmake_minimum_required(VERSION 3.16)

project(i3blocks)
enable_language(C ASM)
include(GNUInstallDirs)
###############################################################################
## file globbing ##############################################################
###############################################################################

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")

set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  message("Debug build.")
elseif(CMAKE_BUILD_TYPE MATCHES Release)
  message("Release build.")
else()
  message("Some other build type. Setting up default = Release")
  set(CMAKE_BUILD_TYPE Debug)
endif()

file(GLOB_RECURSE sources      src/*.c src/*.s inc/*.h)
file(GLOB_RECURSE sources_test tests/*.c)
file(GLOB_RECURSE data resources/*)

option(ENABLE_BASH_COMPLETION "Install bash completion for i3blocks" ON)
# Default path similar to many distros:
set(BASH_COMPLETION_DIR
    "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
    CACHE PATH "Directory for bash-completion files")

###############################################################################
## target definitions #########################################################
###############################################################################

set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "1.5.01")

add_compile_definitions(
  PACKAGE_NAME="${CPACK_PACKAGE_NAME} ${CPACK_PACKAGE_VERSION}"
  PACKAGE_VERSION="${CPACK_PACKAGE_VERSION}"
  SYSCONFDIR=\"${CMAKE_INSTALL_FULL_SYSCONFDIR}\"
)

add_executable(${PROJECT_NAME} ${sources} ${data})
target_include_directories(${PROJECT_NAME} PRIVATE inc)

set(warning_level -Wall -Wextra -pedantic)
target_compile_options(${PROJECT_NAME} PUBLIC ${warning_level} ${sse_flags})

# This copies all resource files in the build directory.
# We need this, because we want to work with paths relative to the executable.
file(COPY ${data} DESTINATION resources)

# All install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_NAME}_destination)

# This is basically a repeat of the file copy instruction that copies the
# resources in the build directory, but here we tell cmake that we want it
# in the package.
install(DIRECTORY resources DESTINATION ${PROJECT_NAME}_destination)

# Manpage: install to share/man/man1
install(FILES docs/i3blocks.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

# Default config: install to sysconfdir (e.g. /etc)
install(FILES i3blocks.conf
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})

if(ENABLE_BASH_COMPLETION)
  install(FILES bash-completion
          DESTINATION "${BASH_COMPLETION_DIR}"
          RENAME i3blocks)
endif()

set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)
