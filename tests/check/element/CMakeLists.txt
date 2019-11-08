set(SUPRESSIONS "${CMAKE_CURRENT_SOURCE_DIR}/../valgrind.supp")

if(${ENABLE_EXPERIMENTAL_TESTS})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_EXPERIMENTAL_TESTS")
endif()


add_test_program(test_siprtpendpoint siprtpendpoint.c)
#add_dependencies(test_siprtpendpoint ${LIBRARY_NAME}plugins)
add_dependencies(test_siprtpendpoint ${LIBRARY_NAME}module)
target_include_directories(test_siprtpendpoint PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/..
                           ${KmsGstCommons_INCLUDE_DIRS}
                           ${gstreamer-1.5_INCLUDE_DIRS}
                           ${gstreamer-check-1.5_INCLUDE_DIRS})
target_link_libraries(test_siprtpendpoint
                      ${gstreamer-1.5_LIBRARIES}
                      ${gstreamer-sdp-1.5_LIBRARIES}
                      ${gstreamer-check-1.5_LIBRARIES}
                      ${KmsGstCommons_LIBRARIES}
                      ${KMSCORE_LIBRARIES}
                      kmstestutils)

add_test_program(test_siprtpendpoint_audio siprtpendpoint_audio.c)
#add_dependencies(test_siprtpendpoint_audio ${LIBRARY_NAME}plugins)
add_dependencies(test_siprtpendpoint_audio ${LIBRARY_NAME}module)
target_include_directories(test_siprtpendpoint_audio PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/..
                           ${KmsGstCommons_INCLUDE_DIRS}
                           ${gstreamer-1.5_INCLUDE_DIRS}
                           ${gstreamer-check-1.5_INCLUDE_DIRS})
target_link_libraries(test_siprtpendpoint_audio
                      ${gstreamer-1.5_LIBRARIES}
                      ${gstreamer-sdp-1.5_LIBRARIES}
                      ${gstreamer-check-1.5_LIBRARIES}
                      ${KmsGstCommons_LIBRARIES})

# add_test_program(test_rtpendpoint_video rtpendpoint_video.c)
# add_dependencies(test_rtpendpoint_video kmstestutils ${LIBRARY_NAME}plugins)
# target_include_directories(test_rtpendpoint_video PRIVATE
#                            ${KmsGstCommons_INCLUDE_DIRS}
#                            ${gstreamer-1.5_INCLUDE_DIRS}
#                            ${gstreamer-check-1.5_INCLUDE_DIRS})
# target_link_libraries(test_rtpendpoint_video
#                       ${gstreamer-1.5_LIBRARIES}
#                       ${gstreamer-check-1.5_LIBRARIES}
#                       ${KmsGstCommons_LIBRARIES}
#                       kmstestutils)


add_test_program(test_sipsrtp sipsrtp.c)
#add_dependencies(test_sipsrtp ${LIBRARY_NAME}plugins)
add_dependencies(test_sipsrtp ${LIBRARY_NAME}module)
target_include_directories(test_sipsrtp PRIVATE
                           ${gstreamer-1.5_INCLUDE_DIRS}
                           ${gstreamer-rtp-1.5_INCLUDE_DIRS}
                           ${gstreamer-check-1.5_INCLUDE_DIRS}
                           ${KmsGstCommons_INCLUDE_DIRS})
target_link_libraries(test_sipsrtp
                      ${gstreamer-1.5_LIBRARIES}
                      ${gstreamer-rtp-1.5_LIBRARIES}
                      ${gstreamer-check-1.5_LIBRARIES}
                      ${KmsGstCommons_LIBRARIES}
                      ${KMSCORE_LIBRARIES}
  					  ${KMS_ELEMENTS_LIBRARIES}
                      ${KMSGSTCOMMONS_LIBRARIES}
                      ${GSTREAMER_LIBRARIES}
                      ${GSTREAMER_VIDEO_LIBRARIES}
                      ${GSTREAMER_CHECK_LIBRARIES}
                       kmstestutils)
                      
