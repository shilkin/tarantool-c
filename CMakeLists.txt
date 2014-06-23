cmake_minimum_required(VERSION 2.6)

project(LIBTP)

set(LIBTP_NAME "tp")
set(LIBTP_VERSIONMAJOR "1")
set(LIBTP_VERSIONMINOR "1")
set(LIBTP_VERSION "${LIBTP_VERSIONMAJOR}.${LIBTP_VERSIONMINOR}")
set(LIBTP_SOVERSION "${LIBTP_VERSIONMAJOR}")
set(LIBTP_CFLAGS "-std=gnu99 -Wall -Wextra -g")
set(LIBTP_ROOT "")

if (DEFINED ${TARANTOOL_PRODUCT})
	set(LIBTP_ROOT "${PROJECT_SOURCE_DIR}/connector/c/tp")
else()
	set(LIBTP_ROOT "${PROJECT_SOURCE_DIR}")
endif()

add_definitions("-DTP_LOCAL=${LIBTP_ROOT}/src")

include_directories("${LIBTP_ROOT}" "${LIBTP_ROOT}/src" "${LIBTP_ROOT}/src/msgpuck" "${LIBTP_ROOT}/src/third_party")

set(LIBTP_SRC ${LIBTP_ROOT}/src/tp_io.c ${LIBTP_ROOT}/src/msgpuck/msgpuck.c ${LIBTP_ROOT}/src/third_party/base64.c ${LIBTP_ROOT}/src/third_party/sha1.c)

add_library(tp STATIC ${LIBTP_SRC})

set_target_properties(tp PROPERTIES COMPILE_FLAGS "${LIBTP_CFLAGS}")
set_target_properties(tp PROPERTIES VERSION ${LIBTP_VERSION} SOVERSION ${LIBTP_SOVERSION})
set_target_properties(tp PROPERTIES OUTPUT_NAME ${LIBTP_NAME})

project(LIBTP_SHARED)

add_library(tp_shared SHARED SHARED ${LIBTP_SRC})

string(REPLACE "-static-libgcc" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REPLACE "-static" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

set_target_properties(tp_shared PROPERTIES COMPILE_FLAGS "${LIBTP_CFLAGS}")
set_target_properties(tp_shared PROPERTIES VERSION ${LIBTP_VERSION} SOVERSION ${LIBTP_SOVERSION})
set_target_properties(tp_shared PROPERTIES OUTPUT_NAME ${LIBTP_NAME})

#install(TARGETS tp ARCHIVE DESTINATION lib)
#install(TARGETS tp_shared LIBRARY DESTINATION lib)

#install(FILES
#        ${LIBTP_ROOT}/lib/file.h
#        ${LIBTP_ROOT}/lib/request.h
#        ${LIBTP_ROOT}/lib/session.h
#        ${LIBTP_ROOT}/lib/console.h
#        ${LIBTP_ROOT}/lib/utf8.h
#        ${LIBTP_ROOT}/lib/lex.h
#        ${LIBTP_ROOT}/lib/tp.h
#        DESTINATION include/tarantool)
#install(FILES ${LIBTP_ROOT}/lib/tarantool.h
#        DESTINATION include)

add_subdirectory(test)

message(STATUS "")
message(STATUS "Tarantool library configuration:")
message(STATUS "")
message(STATUS "VERSION: lib${LIBTP_NAME}.so.${LIBTP_VERSION}")
message(STATUS "C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "C_FLAGS: ${LIBTP_CFLAGS}")
message(STATUS "LOCATION: ${LIBTP_ROOT}")
message(STATUS "PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
