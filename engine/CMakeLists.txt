cmake_minimum_required(VERSION 3.16)
project(novawaf_engine CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 平台无关头文件路径
include_directories(${CMAKE_SOURCE_DIR}/include)

# 性能优化选项
add_compile_options(-O2 -Wall -Wextra -Wno-unused-parameter -pthread)

# ---- Linux 检测引擎可执行文件 ----
if(UNIX AND NOT APPLE)
    add_executable(novawaf-engine src/main.cpp)
    target_link_libraries(novawaf-engine pthread)
endif()

# ---- 单元测试（平台无关，Windows/Linux 均可） ----
enable_testing()
add_executable(test_core tests/test_core.cpp)
add_test(NAME test_core COMMAND test_core)
