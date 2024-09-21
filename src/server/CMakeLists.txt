cmake_minimum_required (VERSION 3.5)


set(KMS_ELEMENTS_IMPL_SOURCES
  implementation/objects/ComposedObjectImpl.cpp
  implementation/objects/FacadeRtpEndpointImpl.cpp
)

set(KMS_ELEMENTS_IMPL_HEADERS
  implementation/objects/ComposedObjectImpl.hpp
  implementation/objects/FacadeRtpEndpointImpl.hpp
)
include (CodeGenerator)

generate_code (
  MODELS ${CMAKE_CURRENT_SOURCE_DIR}/interface
    SERVER_IMPL_LIB_EXTRA_SOURCES
      ${KMS_ELEMENTS_IMPL_SOURCES}
  SERVER_IMPL_LIB_EXTRA_HEADERS
      ${KMS_ELEMENTS_IMPL_HEADERS}
  SERVER_STUB_DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/implementation/objects
)
