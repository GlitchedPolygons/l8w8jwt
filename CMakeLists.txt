#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.1)
project(l8w8jwt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

if (WIN32 AND BUILD_SHARED_LIBS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

option(L8W8JWT_ENABLE_TESTS "Build l8w8jwt tests." OFF)
option(L8W8JWT_ENABLE_EXAMPLES "Build l8w8jwt example programs." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

if (NOT TARGET mbedtls)
    add_subdirectory(lib/mbedtls mbedtls)
endif ()

set(l8w8jwt_headers
        ${CMAKE_CURRENT_LIST_DIR}/lib/jsmn/jsmn.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include/chillbuff.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/checknum/include/checknum.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/retcodes.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/algs.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/base64.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/claim.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/encode.h
        ${CMAKE_CURRENT_LIST_DIR}/include/l8w8jwt/decode.h
        )

set(l8w8jwt_sources
        ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
        ${CMAKE_CURRENT_LIST_DIR}/src/claim.c
        ${CMAKE_CURRENT_LIST_DIR}/src/encode.c
        ${CMAKE_CURRENT_LIST_DIR}/src/decode.c
        )

add_library(l8w8jwt ${l8w8jwt_headers} ${l8w8jwt_sources})

target_include_directories(l8w8jwt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include)
target_include_directories(l8w8jwt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/checknum/include)
target_include_directories(l8w8jwt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include)
target_include_directories(l8w8jwt PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/jsmn)
target_include_directories(l8w8jwt PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(l8w8jwt PRIVATE mbedtls mbedx509 mbedcrypto)

if (L8W8JWT_ENABLE_EXAMPLES)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples)
endif ()

if (L8W8JWT_ENABLE_TESTS)

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--wrap=malloc,--wrap=calloc")

    if (WIN32 AND BUILD_SHARED_LIBS)
        set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif ()

    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests/cmocka cmocka)

    set(TESTS 
            ${CMAKE_CURRENT_LIST_DIR}/tests/testkeys.h 
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            )
    
    add_executable(run_tests ${TESTS})

    target_include_directories(run_tests PUBLIC ${cmocka_INCLUDE_DIR})
    target_link_libraries(run_tests PUBLIC l8w8jwt cmocka)

    if (ENABLE_COVERAGE)
        if (L8W8JWT_ENABLE_EXAMPLES)
            message (FATAL_ERROR "ENABLE_COVERAGE and L8W8JWT_ENABLE_EXAMPLES are MUTUALLY EXCLUSIVE! Please enable either one or the other, but not both at the same time!")
        else ()
            find_package(codecov)
            add_coverage(l8w8jwt)
            add_coverage(run_tests)
            coverage_evaluate()
        endif ()
    endif ()
endif()
