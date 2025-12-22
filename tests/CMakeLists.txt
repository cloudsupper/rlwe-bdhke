# Find or download Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Add test executable
add_executable(rlwe_tests
    rlwe_test.cpp
    polynomial_test.cpp
    sha256_test.cpp
    ntt_test.cpp
)

# Link against Google Test and our library
target_link_libraries(rlwe_tests
    PRIVATE
        gtest_main
        rlwe
)

# Add the test to CTest
add_test(NAME rlwe_tests COMMAND rlwe_tests)
