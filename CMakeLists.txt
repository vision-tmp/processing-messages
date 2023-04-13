cmake_minimum_required(VERSION 3.10)

project(process_messages LANGUAGES C)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_C_FLAGS "-Wall")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LOG")

set(SOURCE_DIR src)
add_executable(process_messages ${SOURCE_DIR}/main.c ${SOURCE_DIR}/process_messages.c)
