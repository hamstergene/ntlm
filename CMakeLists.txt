project(ntlm)

set(OPENSSL_USE_STATIC_LIBS ON )
find_package(OpenSSL REQUIRED )

add_library(${PROJECT_NAME}
    ntlm.cpp
    util.cpp
    libcrypto-compat.c

    include/ntlm/ntlm.h
    util.h
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Werror
)

target_include_directories(${PROJECT_NAME} BEFORE
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"

    PRIVATE
        "${OPENSSL_INCLUDE_DIR}"
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        "${OPENSSL_LIBRARIES}"
)
