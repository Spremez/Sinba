cmake_minimum_required(VERSION 3.16)
project(batch_pir_seal LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default build type (bench-like)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(PIR_ENABLE_LOGS "Enable verbose logs" OFF)

# ---------------------------------------------------------------------------
# Microsoft SEAL
#
# Build options:
#   1) System install: set SEAL_DIR to your SEALConfig.cmake directory
#      cmake -DSEAL_DIR=/path/to/seal/cmake ..
#   2) Add SEAL as a subdirectory (e.g., vendor/SEAL)
#      - Put SEAL source at vendor/SEAL and set -DPIR_USE_SEAL_SUBDIR=ON
# ---------------------------------------------------------------------------
option(PIR_USE_SEAL_SUBDIR "Use vendor/SEAL as subdirectory" OFF)

if(PIR_USE_SEAL_SUBDIR)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/SEAL/CMakeLists.txt")
    message(FATAL_ERROR "PIR_USE_SEAL_SUBDIR=ON but vendor/SEAL not found")
  endif()
  add_subdirectory(vendor/SEAL)
else()
  find_package(SEAL 4.1 CONFIG REQUIRED)
endif()

# ---------------------------------------------------------------------------
# Unified compile options (bench-like flags)
# ---------------------------------------------------------------------------
add_library(project_compile_options INTERFACE)
target_compile_options(project_compile_options INTERFACE
  $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
  $<$<CONFIG:RelWithDebInfo>:-O3 -DNDEBUG -march=native>
  $<$<CONFIG:Debug>:-O0 -g>
)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
endif()

# ---------------------------------------------------------------------------
# Core libraries (split like your working project)
# ---------------------------------------------------------------------------

# DB encode
add_library(db_encode_lib STATIC
  src/db_encode.cpp
)
target_include_directories(db_encode_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(db_encode_lib PRIVATE project_compile_options)

# Client
add_library(pir_client_lib STATIC
  src/pir_client.cpp
)
target_include_directories(pir_client_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pir_client_lib PRIVATE project_compile_options db_encode_lib)

# Server
add_library(pir_server_lib STATIC
  src/pir_server.cpp
)
target_include_directories(pir_server_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pir_server_lib PRIVATE project_compile_options db_encode_lib pir_client_lib)

# Link SEAL targets to all libs that need it
if(TARGET SEAL::seal)
  target_link_libraries(db_encode_lib PRIVATE SEAL::seal)
  target_link_libraries(pir_client_lib PRIVATE SEAL::seal)
  target_link_libraries(pir_server_lib PRIVATE SEAL::seal)
elseif(TARGET seal)
  target_link_libraries(db_encode_lib PRIVATE seal)
  target_link_libraries(pir_client_lib PRIVATE seal)
  target_link_libraries(pir_server_lib PRIVATE seal)
else()
  message(FATAL_ERROR "Cannot find SEAL target. Expected SEAL::seal or seal")
endif()

# Compile definitions (logs off by default for accurate bench)
if(PIR_ENABLE_LOGS)
  target_compile_definitions(db_encode_lib PUBLIC PIR_SERVER_LOG_LEVEL=1 PIR_TEST_VERBOSE=1)
  target_compile_definitions(pir_client_lib PUBLIC PIR_SERVER_LOG_LEVEL=1 PIR_TEST_VERBOSE=1)
  target_compile_definitions(pir_server_lib PUBLIC PIR_SERVER_LOG_LEVEL=1 PIR_TEST_VERBOSE=1)
else()
  target_compile_definitions(db_encode_lib PUBLIC PIR_SERVER_LOG_LEVEL=0 PIR_TEST_VERBOSE=0)
  target_compile_definitions(pir_client_lib PUBLIC PIR_SERVER_LOG_LEVEL=0 PIR_TEST_VERBOSE=0)
  target_compile_definitions(pir_server_lib PUBLIC PIR_SERVER_LOG_LEVEL=0 PIR_TEST_VERBOSE=0)
endif()

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
function(add_pir_exe name src)
  add_executable(${name} ${src})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(${name} PRIVATE project_compile_options pir_server_lib pir_client_lib db_encode_lib)

  # Link SEAL to executables too (safe; transitive should work but keep explicit)
  if(TARGET SEAL::seal)
    target_link_libraries(${name} PRIVATE SEAL::seal)
  elseif(TARGET seal)
    target_link_libraries(${name} PRIVATE seal)
  endif()

  set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

  if(${name} STREQUAL "pir_test")
    if(PIR_ENABLE_LOGS)
      target_compile_definitions(${name} PRIVATE PIR_SERVER_LOG_LEVEL=1 PIR_TEST_VERBOSE=1)
    else()
      target_compile_definitions(${name} PRIVATE PIR_SERVER_LOG_LEVEL=0 PIR_TEST_VERBOSE=0)
    endif()
  else()
    target_compile_definitions(${name} PRIVATE PIR_SERVER_LOG_LEVEL=0)
  endif()
endfunction()

add_pir_exe(pir_test src/pir_test.cpp)
add_pir_exe(seal_bench_comparison src/seal_bench_comparison.cpp)

message(STATUS "======================================")
message(STATUS "batch_pir_seal project configuration")
message(STATUS "=======================================")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "LTO/IPO(Release): ${CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE}")
message(STATUS "PIR_ENABLE_LOGS: ${PIR_ENABLE_LOGS}")
message(STATUS "PIR_USE_SEAL_SUBDIR: ${PIR_USE_SEAL_SUBDIR}")
message(STATUS "=======================================")
