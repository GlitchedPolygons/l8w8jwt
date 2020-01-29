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

add_subdirectory(../ lib)

add_executable(l8w8jwt_example_hs256_encode hs256/encode.c)
add_executable(l8w8jwt_example_hs384_encode hs384/encode.c)
add_executable(l8w8jwt_example_hs512_encode hs512/encode.c)

add_executable(l8w8jwt_example_rs256_encode rs256/encode.c)
add_executable(l8w8jwt_example_rs384_encode rs384/encode.c)
add_executable(l8w8jwt_example_rs512_encode rs512/encode.c)

add_executable(l8w8jwt_example_es256_encode es256/encode.c)
add_executable(l8w8jwt_example_es384_encode es384/encode.c)
add_executable(l8w8jwt_example_es512_encode es512/encode.c)

add_executable(l8w8jwt_example_ps256_encode ps256/encode.c)
add_executable(l8w8jwt_example_ps384_encode ps384/encode.c)
add_executable(l8w8jwt_example_ps512_encode ps512/encode.c)

target_link_libraries(l8w8jwt_example_hs256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs512_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_rs256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs512_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_es256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es512_encode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_ps256_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps384_encode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps512_encode PRIVATE l8w8jwt)

add_executable(l8w8jwt_example_hs256_decode hs256/decode.c)
add_executable(l8w8jwt_example_hs384_decode hs384/decode.c)
add_executable(l8w8jwt_example_hs512_decode hs512/decode.c)

add_executable(l8w8jwt_example_rs256_decode rs256/decode.c)
add_executable(l8w8jwt_example_rs384_decode rs384/decode.c)
add_executable(l8w8jwt_example_rs512_decode rs512/decode.c)

add_executable(l8w8jwt_example_es256_decode es256/decode.c)
add_executable(l8w8jwt_example_es384_decode es384/decode.c)
add_executable(l8w8jwt_example_es512_decode es512/decode.c)

add_executable(l8w8jwt_example_ps256_decode ps256/decode.c)
add_executable(l8w8jwt_example_ps384_decode ps384/decode.c)
add_executable(l8w8jwt_example_ps512_decode ps512/decode.c)

target_link_libraries(l8w8jwt_example_hs256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs512_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_rs256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs512_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_es256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es512_decode PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_ps256_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps384_decode PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps512_decode PRIVATE l8w8jwt)