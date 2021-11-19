set(TEST_VARIABLES
  "GST_PLUGIN_PATH=$ENV{GST_PLUGIN_PATH}:${CMAKE_BINARY_DIR}:${CMAKE_BINARY_DIR}/src"
)
set(VALGRIND_TEST_VARIABLES
  "${TEST_VARIABLES}"
  "DEBUG_MEDIASET=TRUE"
)
list(APPEND SUPPRESSIONS
  "${CMAKE_CURRENT_SOURCE_DIR}/valgrind.supp")

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})

    message("Boost VERSION: ${Boost_VERSION}")
    message("Boost INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
    message("Boost Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
    message("Boost LIBRARIES: ${Boost_SYSTEM_LIBRARY}")
endif ()


add_test_program(test_constructors constructors.cpp)
if(TARGET ${LIBRARY_NAME}module)
  add_dependencies(test_constructors ${LIBRARY_NAME}module)
endif()
add_dependencies(test_constructors kmssiprtpmodule)
#add_dependencies(test_constructors ${LIBRARY_NAME}plugins)
set_property(TARGET test_constructors
  PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_BINARY_DIR}/../..
    ${JSONRPC_INCLUDE_DIRS}
    ${SIGCPP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_constructors
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  -lgmodule-2.0
  ${glibmm-2.0_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)

# add_test_program(test_webrtc_endpoint webRtcEndpoint.cpp)
# add_dependencies(test_webrtc_endpoint kmselementsplugins ${LIBRARY_NAME}impl)
# set_property(TARGET test_webrtc_endpoint
#   PROPERTY INCLUDE_DIRECTORIES
#     ${KmsJsonRpc_INCLUDE_DIRS}
#     ${sigc++-2.0_INCLUDE_DIRS}
#     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
#     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
#     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
#     ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
#     ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
#     ${KMSCORE_INCLUDE_DIRS}
#     ${glibmm-2.4_INCLUDE_DIRS}
#     ${gstreamer-1.5_INCLUDE_DIRS}
# )
# target_link_libraries(test_webrtc_endpoint
#   ${LIBRARY_NAME}impl
#   ${KMSCORE_LIBRARIES}
#   ${glibmm-2.4_LIBRARIES}
# )

add_test_program(test_sip_rtp_endpoint sipRtpEndpoint.cpp)
add_dependencies(test_sip_rtp_endpoint kmssiprtpmodule)
set_property(TARGET test_sip_rtp_endpoint
  PROPERTY INCLUDE_DIRECTORIES
    ${KmsJsonRpc_INCLUDE_DIRS}
    ${sigc++-2.0_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_sip_rtp_endpoint
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)

add_test_program(test_sip_rtp_endpoint_play sipRtpEndpointPlay.cpp)
add_dependencies(test_sip_rtp_endpoint_play kmssiprtpmodule)
set_property(TARGET test_sip_rtp_endpoint_play
  PROPERTY INCLUDE_DIRECTORIES
    ${KmsJsonRpc_INCLUDE_DIRS}
    ${sigc++-2.0_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_sip_rtp_endpoint_play
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)

add_test_program(test_sip_rtp_endpoint_agnostic_srtp sipRtpEndpoint_agnostic_srtp.cpp)
add_dependencies(test_sip_rtp_endpoint_agnostic_srtp kmssiprtpmodule)
set_property(TARGET test_sip_rtp_endpoint_agnostic_srtp
  PROPERTY INCLUDE_DIRECTORIES
    ${KmsJsonRpc_INCLUDE_DIRS}
    ${sigc++-2.0_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_sip_rtp_endpoint_agnostic_srtp
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)


add_test_program(test_event_forwarding eventForwarding.cpp)
add_dependencies(test_event_forwarding kmssiprtpmodule)
set_property(TARGET test_event_forwarding
  PROPERTY INCLUDE_DIRECTORIES
    ${KmsJsonRpc_INCLUDE_DIRS}
    ${sigc++-2.0_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_event_forwarding
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)


add_test_program(test_source_connections sourceConnections.cpp)
add_dependencies(test_source_connections kmssiprtpmodule)
set_property(TARGET test_source_connections
  PROPERTY INCLUDE_DIRECTORIES
    ${KmsJsonRpc_INCLUDE_DIRS}
    ${sigc++-2.0_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation/objects
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/implementation
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/server/interface
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/interface/generated-cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/server/implementation/generated-cpp
    ${KMSCORE_INCLUDE_DIRS}
    ${gstreamer-1.5_INCLUDE_DIRS}
)
target_link_libraries(test_source_connections
  ${LIBRARY_NAME}impl
  ${KMSCORE_LIBRARIES}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)
