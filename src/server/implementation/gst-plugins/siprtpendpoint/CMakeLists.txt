cmake_minimum_required(VERSION 2.8)

set(KMS_SIPRTPENDPOINT_SOURCES
  kmssiprtpconnection.c
  kmssipsrtpconnection.c
  kmssiprtpsession.c
  kmssipsrtpsession.c
  kmssiprtpendpoint.c
)

set(KMS_SIPRTPENDPOINT_HEADERS
  kmssiprtpendpoint.h
)

set(ENUM_HEADERS
)

list(APPEND KMS_SIPRTPENDPOINT_HEADERS ${ENUM_HEADERS})
add_glib_enumtypes(KMS_SIPRTPENDPOINT_SOURCES KMS_SIPRTPENDPOINT_HEADERS kms-rtp-enumtypes KMS ${ENUM_HEADERS})

add_library(siprtpendpoint MODULE ${KMS_SIPRTPENDPOINT_SOURCES} ${KMS_SIPRTPENDPOINT_HEADERS})
if(SANITIZERS_ENABLED)
  add_sanitizers(siprtpendpoint)
endif()

add_dependencies(siprtpendpoint rtcpdemux)

set_property(TARGET siprtpendpoint
  PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/../../..
    ${KmsGstCommons_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)

target_link_libraries(siprtpendpoint
  ${KmsGstCommons_LIBRARIES}
  ${gstreamer-1.5_LIBRARIES}
  ${gstreamer-base-1.5_LIBRARIES}
  ${gstreamer-sdp-1.5_LIBRARIES}
  ${gstreamer-pbutils-1.5_LIBRARIES}
  ${nice_LIBRARIES}
)

install(
  TARGETS siprtpendpoint
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_GST_PLUGINS_DIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
