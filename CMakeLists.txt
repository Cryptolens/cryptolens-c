cmake_minimum_required (VERSION 3.0.2)
project (cryptolens)

find_package(OpenSSL)

add_library (cryptolens STATIC "src/cryptolens.c" "src/data_object.c" "src/decode_base64.c" "src/error.c" "src/machine_code_computer_static.c" "src/request_handler_curl.c" "src/response_parser_cJSON.c" "src/signature_verifier_openssl.c" "third_party/cJSON/cJSON.c" "third_party/openbsd/base64.c" "third_party/openbsd/strlcpy.c")
target_link_libraries (cryptolens crypto ssl curl)
target_include_directories (cryptolens PUBLIC "include/")
target_include_directories (cryptolens PRIVATE "third_party/cJSON/")
