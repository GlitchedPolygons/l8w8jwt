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

add_executable(l8w8jwt_example_hs256 hs256/main.c)
add_executable(l8w8jwt_example_hs384 hs384/main.c)
add_executable(l8w8jwt_example_hs512 hs512/main.c)

add_executable(l8w8jwt_example_rs256 rs256/main.c)
add_executable(l8w8jwt_example_rs384 rs384/main.c)
add_executable(l8w8jwt_example_rs512 rs512/main.c)

add_executable(l8w8jwt_example_es256 es256/main.c)
add_executable(l8w8jwt_example_es384 es384/main.c)
add_executable(l8w8jwt_example_es512 es512/main.c)

add_executable(l8w8jwt_example_ps256 ps256/main.c)
add_executable(l8w8jwt_example_ps384 ps384/main.c)
add_executable(l8w8jwt_example_ps512 ps512/main.c)

target_link_libraries(l8w8jwt_example_hs256 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs384 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_hs512 PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_rs256 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs384 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_rs512 PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_es256 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es384 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_es512 PRIVATE l8w8jwt)

target_link_libraries(l8w8jwt_example_ps256 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps384 PRIVATE l8w8jwt)
target_link_libraries(l8w8jwt_example_ps512 PRIVATE l8w8jwt)
