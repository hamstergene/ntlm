project(ntlm)

find_package(OpenSSL 1.1 REQUIRED)

add_library(${PROJECT_NAME}
    ntlm.cpp
    util.cpp

    include/ntlm/ntlm.h
    util.h
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Werror
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"

    PRIVATE
        "${OPENSSL_INCLUDE_DIR}"
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        "${OPENSSL_LIBRARIES}"
)
