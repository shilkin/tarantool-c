project(LIBTP_TEST)

set(LIBTP_TESTNAME "test")
set(LIBTP_TESTSRC test.c)

set(LIBTP_TESTCFLAGS "-std=gnu99 -Wall -Wextra -g")

add_executable(${LIBTP_TESTNAME} ${LIBTP_TESTSRC})
target_link_libraries(${LIBTP_TESTNAME} tp)
set_target_properties(${LIBTP_TESTNAME} PROPERTIES COMPILE_FLAGS "${LIBTP_TESTCFLAGS}")

add_custom_target(connector_test COMMAND ${PROJECT_BINARY_DIR}/suite)
