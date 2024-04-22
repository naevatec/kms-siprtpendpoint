include_directories(
  ${KMSCORE_INCLUDE_DIRS}
  ${KMS_ELEMENTS_INCLUDE_DIRS}
  ${KMSGSTCOMMONS_INCLUDE_DIRS}
  ${KmsRtpEndpointLib_INCLUDE_DIR}
  ${GSTREAMER_INCLUDE_DIRS}
  ${GSTREAMER_VIDEO_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set(SIPRTP_SOURCES
  kmssiprtpendpoint.c kmssiprtpendpoint.h
  kmssiprtpconnection.c kmssiprtpconnection.h
  kmssiprtpsession.c kmssiprtpsession.h
  kmssipsrtpconnection.c kmssipsrtpconnection.h
  kmssipsrtpsession.c kmssipsrtpsession.h  
  kmsrtpfilterutils.c kmsrtpfilterutils.h
)

add_library(siprtpendpoint MODULE ${SIPRTP_SOURCES})

# This target uses 'setenv()', which is a POSIX.1-2001 extension
target_compile_definitions(siprtpendpoint PRIVATE _POSIX_C_SOURCE=200112L)

target_link_libraries(siprtpendpoint
  ${KmsRtpEndpointLib_LIBRARY}
  ${KMSCORE_LIBRARIES}
  ${KMS_ELEMENTS_LIBRARIES}
  ${KMSGSTCOMMONS_LIBRARIES}
  -lgstnet-1.0
  ${GSTREAMER_LIBRARIES}
  ${GSTREAMER_VIDEO_LIBRARIES}
)

foreach(lib ${KMS_ELEMENTS_LIBRARIES})
  message(STATUS "lib='${lib}'")
endforeach()
  

install(
  TARGETS siprtpendpoint
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_GST_PLUGINS_DIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
