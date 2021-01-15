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
set(CMAKE_C_STANDARD 11)
project(l8w8jwt_examples C)

add_executable(l8w8jwt_example_hs256_encode ${CMAKE_CURRENT_LIST_DIR}/hs256/encode.c)
add_executable(l8w8jwt_example_hs384_encode ${CMAKE_CURRENT_LIST_DIR}/hs384/encode.c)
add_executable(l8w8jwt_example_hs512_encode ${CMAKE_CURRENT_LIST_DIR}/hs512/encode.c)

add_executable(l8w8jwt_example_rs256_encode ${CMAKE_CURRENT_LIST_DIR}/rs256/encode.c)
add_executable(l8w8jwt_example_rs384_encode ${CMAKE_CURRENT_LIST_DIR}/rs384/encode.c)
add_executable(l8w8jwt_example_rs512_encode ${CMAKE_CURRENT_LIST_DIR}/rs512/encode.c)

add_executable(l8w8jwt_example_es256_encode ${CMAKE_CURRENT_LIST_DIR}/es256/encode.c)
add_executable(l8w8jwt_example_es256k_encode ${CMAKE_CURRENT_LIST_DIR}/es256k/encode.c)
add_executable(l8w8jwt_example_es384_encode ${CMAKE_CURRENT_LIST_DIR}/es384/encode.c)
add_executable(l8w8jwt_example_es512_encode ${CMAKE_CURRENT_LIST_DIR}/es512/encode.c)
add_executable(l8w8jwt_example_eddsa_encode ${CMAKE_CURRENT_LIST_DIR}/eddsa/encode.c)

add_executable(l8w8jwt_example_ps256_encode ${CMAKE_CURRENT_LIST_DIR}/ps256/encode.c)
add_executable(l8w8jwt_example_ps384_encode ${CMAKE_CURRENT_LIST_DIR}/ps384/encode.c)
add_executable(l8w8jwt_example_ps512_encode ${CMAKE_CURRENT_LIST_DIR}/ps512/encode.c)

target_link_libraries(l8w8jwt_example_hs256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs512_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_rs256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs512_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_es256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es256k_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es512_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_eddsa_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_ps256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps512_encode PRIVATE l8w8jwt)

add_executable(l8w8jwt_example_hs256_decode ${CMAKE_CURRENT_LIST_DIR}/hs256/decode.c)
add_executable(l8w8jwt_example_hs384_decode ${CMAKE_CURRENT_LIST_DIR}/hs384/decode.c)
add_executable(l8w8jwt_example_hs512_decode ${CMAKE_CURRENT_LIST_DIR}/hs512/decode.c)

add_executable(l8w8jwt_example_rs256_decode ${CMAKE_CURRENT_LIST_DIR}/rs256/decode.c)
add_executable(l8w8jwt_example_rs384_decode ${CMAKE_CURRENT_LIST_DIR}/rs384/decode.c)
add_executable(l8w8jwt_example_rs512_decode ${CMAKE_CURRENT_LIST_DIR}/rs512/decode.c)

add_executable(l8w8jwt_example_es256_decode ${CMAKE_CURRENT_LIST_DIR}/es256/decode.c)
add_executable(l8w8jwt_example_es256k_decode ${CMAKE_CURRENT_LIST_DIR}/es256k/decode.c)
add_executable(l8w8jwt_example_es384_decode ${CMAKE_CURRENT_LIST_DIR}/es384/decode.c)
add_executable(l8w8jwt_example_es512_decode ${CMAKE_CURRENT_LIST_DIR}/es512/decode.c)
add_executable(l8w8jwt_example_eddsa_decode ${CMAKE_CURRENT_LIST_DIR}/eddsa/decode.c)

add_executable(l8w8jwt_example_ps256_decode ${CMAKE_CURRENT_LIST_DIR}/ps256/decode.c)
add_executable(l8w8jwt_example_ps384_decode ${CMAKE_CURRENT_LIST_DIR}/ps384/decode.c)
add_executable(l8w8jwt_example_ps512_decode ${CMAKE_CURRENT_LIST_DIR}/ps512/decode.c)

target_link_libraries(l8w8jwt_example_hs256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs512_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_rs256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs512_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_es256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es256k_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es512_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_eddsa_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_ps256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps512_decode PRIVATE l8w8jwt)

add_executable(l8w8jwt_example_eddsa_generate_keypair ${CMAKE_CURRENT_LIST_DIR}/eddsa/keygen.c)
target_link_libraries(l8w8jwt_example_eddsa_generate_keypair PRIVATE l8w8jwt)