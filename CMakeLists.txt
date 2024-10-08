cmake_minimum_required(VERSION 3.5)

project("kms-siprtpendpoint")
message(STATUS "CMake project: ${PROJECT_NAME}")

# Test configuration
set(GENERATE_TESTS FALSE CACHE BOOL "Always build tests: add `make check_build` to normal `make` calls")
set(DISABLE_TESTS FALSE CACHE BOOL "Enable running `make check` during the building process")
set(VALGRIND_NUM_CALLERS 20 CACHE STRING "Valgrind option: maximum number of entries shown in stack traces")

message("If KurentoHelpers is not found, you need to install 'kms-cmake-utils' from the Kurento repository")
find_package(KurentoUtils  REQUIRED)

message("If CodeGenerator is not found, you need to install 'kms-core' from the Kurento repository")
include(CodeGenerator)
get_values_from_model(PREFIX VALUE MODELS ${CMAKE_CURRENT_SOURCE_DIR}/src/server/interface KEYS version)

include(KurentoGitHelpers)
install_git_hook(pre-commit ${CMAKE_CURRENT_SOURCE_DIR}/hooks/pre-commit.hook)
get_git_version(PROJECT_VERSION ${VALUE_VERSION})
message(STATUS "Project version: ${PROJECT_NAME}-${PROJECT_VERSION}")

# Compiler flags
include(CommonBuildFlags)
common_buildflags_set()
#common_buildflags_print()

# Development: Add here exceptions to the "Warnings are Errors" rule.
# Also, DOCUMENT WHY and always remove them as soon as the problem is fixed.
# For example:
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=unused-function")

# FIXME Disable error when macros __TIME__, __DATE__ or __TIMESTAMP__ are encountered
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-Wno-error=date-time" HAS_WARNING_DATE_TIME)
if(HAS_WARNING_DATE_TIME)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=date-time")
endif()

# Generate file "config.h"
set(VERSION ${PROJECT_VERSION})
set(PACKAGE ${PROJECT_NAME})
set(GETTEXT_PACKAGE "kms-siprtpendpoint")
include(GNUInstallDirs)
set(DATAROOTDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR})
set(MANUAL_CHECK OFF CACHE BOOL "Tests will generate files")
set(BINARY_LOCATION "http://files.openvidu.io/" CACHE STRING "Local binary directory expressed as an URI ( http:// or file:/// )")
set(KURENTO_MODULES_SO_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${KURENTO_MODULES_DIR_INSTALL_PREFIX})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -DHAVE_CONFIG_H")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_CONFIG_H")
include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

set (GST_REQUIRED 1.0.0)
set (GLIB_REQUIRED 2.38)
set (OPENCV_REQUIRED 2.0.0)

include(GenericFind)
find_package(Boost 1.58.0 REQUIRED system filesystem thread)
#generic_find(LIBNAME Boost REQUIRED COMPONENTS system)
generic_find(LIBNAME gstreamer-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-base-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-video-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-app-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-check-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-sdp-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-rtp-1.0 VERSION>=${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-pbutils-1.0 VERSION>= ${GST_REQUIRED} REQUIRED)
generic_find(LIBNAME gstreamer-sctp-1.0 REQUIRED)
generic_find(LIBNAME glibmm-2.4 VERSION ${GLIBMM_REQUIRED} REQUIRED)
generic_find(LIBNAME glib-2.0 VERSION>=${GLIB_REQUIRED} REQUIRED)
generic_find(LIBNAME KmsGstCommons REQUIRED)
generic_find(LIBNAME libsoup-3.0 VERSION ${SOUP_REQUIRED} REQUIRED)
generic_find(LIBNAME nice VERSION ${NICE_REQUIRED} REQUIRED)
generic_find(LIBNAME gio-2.0 VERSION>=${GLIB_REQUIRED} REQUIRED)
generic_find(LIBNAME uuid REQUIRED)
generic_find(LIBNAME openssl REQUIRED)
generic_find(LIBNAME KmsRtpEndpointLib REQUIRED)

#find_package(PkgConfig)
#pkg_check_modules(GSTREAMER REQUIRED gstreamer-1.5>=${GST_REQUIRED})
#pkg_check_modules(GSTREAMER_BASE REQUIRED gstreamer-base-1.5>=${GST_REQUIRED})
##pkg_check_modules(GSTREAMER_VIDEO REQUIRED gstreamer-video-1.5>=${GST_REQUIRED})
#pkg_check_modules(GSTREAMER_CHECK REQUIRED gstreamer-check-1.5>=${GST_REQUIRED})
#pkg_check_modules(KMSCORE REQUIRED kmscore)
#pkg_check_modules(KMS_ELEMENTS REQUIRED kmselements)
#pkg_check_modules(KMSGSTCOMMONS REQUIRED kmsgstcommons)
#pkg_check_modules(OPENCV REQUIRED opencv>=${OPENCV_REQUIRED})

#include(GenericFind)
#generic_find(LIBNAME Boost REQUIRED COMPONENTS unit_test_framework)

#generic_find(LIBNAME gstreamer-1.5 VERSION ${GST_REQUIRED} REQUIRED)
#generic_find(LIBNAME gstreamer-base-1.5 VERSION ${GST_REQUIRED} REQUIRED)
#generic_find(LIBNAME gstreamer-video-1.5 VERSION ${GST_REQUIRED} REQUIRED)
#generic_find(LIBNAME gstreamer-check-1.5 VERSION ${GST_REQUIRED} REQUIRED)
#generic_find(LIBNAME KmsGstCommons REQUIRED)


set(CMAKE_INSTALL_GST_PLUGINS_DIR ${CMAKE_INSTALL_LIBDIR}/gstreamer-1.0)

enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
