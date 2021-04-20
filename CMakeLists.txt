cmake_minimum_required(VERSION 3.0)

SET(PROJ_NAME CPPCrypto)
project(${PROJ_NAME})

add_compile_options(
    "-maes"
    "-msse2"
)

file(GLOB SRC 
    "src/*.cpp"
    "include/*.h"
)

file(GLOB AESTest
    "tests/AESTest.cpp"    
)

file(GLOB RSATest
    "tests/RSATest.cpp"
)

add_library(${PROJ_NAME} "${SRC}")

add_executable(AESTest "${AESTest}")
add_executable(RSATest "${RSATest}")

target_link_libraries(AESTest ${PROJ_NAME})
target_link_libraries(RSATest ${PROJ_NAME})

include_directories(${PROJECT_SOURCE_DIR}/./include)