cmake_minimum_required(VERSION 3.0)

SET(PROJ_NAME CPPCrypto)
project(${PROJ_NAME})

file(GLOB SRC 
    "src/*.cpp"
    "include/*.h"
)

file(GLOB AESTest
    "tests/AESTest.cpp"    
)

add_library(${PROJ_NAME}
    "${SRC}"
)

add_executable(AESTest
    "${AESTest}"
)

target_link_libraries(AESTest ${PROJ_NAME})

include_directories(${PROJECT_SOURCE_DIR}/./include)