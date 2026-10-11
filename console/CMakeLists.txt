cmake_minimum_required(VERSION 3.16)
project(novawaf-console CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Drogon / jsoncpp 安装在 ~/deps（或 -DCMAKE_PREFIX_PATH 指定）
find_package(Drogon CONFIG REQUIRED)

add_executable(novawaf-console main.cpp)

# 复用引擎的 header-only redis_client.h
target_include_directories(novawaf-console PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../engine/include)

target_link_libraries(novawaf-console PRIVATE
  Drogon::Drogon
  OpenSSL::Crypto
  OpenSSL::SSL)
