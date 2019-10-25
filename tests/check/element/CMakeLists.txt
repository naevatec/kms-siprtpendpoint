set (SUPRESSIONS "${CMAKE_CURRENT_SOURCE_DIR}/../valgrind.supp")

 add_test_program (test_datachannel datachannel.c)
 add_dependencies(test_datachannel datachannel)
 target_include_directories(test_datachannel PRIVATE
         ${KMSCORE_INCLUDE_DIRS}
                            ${GSTREAMER_INCLUDE_DIRS}
                            ${GSTREAMER_CHECK_INCLUDE_DIRS}
                            "${CMAKE_CURRENT_SOURCE_DIR}/../../../src/gst-plugins")
 target_link_libraries(test_datachannel
  					   ${KMSCORE_LIBRARIES}
                       ${KMSGSTCOMMONS_LIBRARIES}
                       ${GSTREAMER_LIBRARIES}
                       ${GSTREAMER_CHECK_LIBRARIES}
                       kmstestutils)
