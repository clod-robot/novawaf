cmake_minimum_required(VERSION 3.16)
project(novawaf_engine CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---- 硬件加速构建选项 ----
# 设计：一份引擎二进制到处运行。GPU/NPU 后端在“运行时”按固定 SONAME 白名单 dlopen，
#       构建期不依赖 CUDA/ROCm/CANN SDK；下列 WITH_* 仅登记能力开关，不引入链接依赖。
option(NOVA_WITH_OPENCL "编入 OpenCL 运行时探测(dlsym，无需 SDK)" ON)
option(NOVA_WITH_CUDA   "编入 CUDA 运行时探测(dlsym，无需 SDK)" ON)
option(NOVA_WITH_HIP    "编入 HIP/海光 DCU 运行时探测(dlsym，无需 SDK)" ON)
option(NOVA_WITH_CANN   "编入昇腾 CANN 运行时探测(dlsym，无需 SDK)" ON)
option(NOVA_FORCE_SCALAR "强制只编译标量后端(关闭 SIMD，用于对照/兼容旧 CPU)" OFF)

# 平台无关头文件路径
include_directories(${CMAKE_SOURCE_DIR}/include)

# 性能优化选项
add_compile_options(-O2 -Wall -Wextra -Wno-unused-parameter -pthread)

# ---- Linux 检测引擎可执行文件 ----
if(UNIX AND NOT APPLE)
    add_executable(novawaf-engine src/main.cpp)
    target_link_libraries(novawaf-engine pthread ${CMAKE_DL_LIBS})
    if(NOVA_FORCE_SCALAR)
        target_compile_definitions(novawaf-engine PRIVATE NOVA_FORCE_SCALAR=1)
    endif()
endif()

# ---- 单元测试（平台无关，Windows/Linux 均可） ----
enable_testing()
add_executable(test_core tests/test_core.cpp)
if(NOVA_FORCE_SCALAR)
    target_compile_definitions(test_core PRIVATE NOVA_FORCE_SCALAR=1)
endif()
add_test(NAME test_core COMMAND test_core)
