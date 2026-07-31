cmake_minimum_required(VERSION 3.16)

project(i3blocks VERSION 0.1 LANGUAGES C)
include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# set(CMAKE_C_COMPILER clang)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  # set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(sources
  # headers
  inc/bar.h                            
  inc/block.h                          
  inc/config.h                         
  inc/ini.h                            
  inc/json.h                           
  inc/line.h                           
  inc/log.h                            
  inc/map.h                            
  inc/sys.h                            
  inc/term.h                           

  # sources
  src/bar.c    
  src/block.c  
  src/config.c 
  src/i3bar.c  
  src/ini.c    
  src/json.c   
  src/line.c   
  src/main.c   
  src/map.c    
  src/sys.c    

  # other files (like ui forms)
)

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

target_compile_options(${PROJECT_NAME} PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  $<$<CONFIG:Release>:-O2>
  $<$<CONFIG:Debug>:-O0 -g>
)

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
