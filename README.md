# Cryptolens Client API for C

This branch is under ongoing development.

## Build instructions

### Visual Studio

Build the project in `vsprojects/Cryptolens` with some platform and configuration (e.g. `Win32` and `Debug`).
This will create the `Cryptolens.lib` file in `vsprojects/Cryptolens/Cryptolens/$(Configuration)` or 
`vsprojects/Cryptolens/Cryptolens/x64/$(Configuration)` for platforms `Win32` and `x64`, respectively.

The `Cryptolens.lib` file can then be used in another project, together with the include files in the
`include/` directory. The `examples/CryptolensExamples` project is setup to build the example file
`examples/example_activate_external.c` in this way.

Thus, to build the example project, first build the library in `vsprojects/Cryptolens` and then build the example
project in `examples/CryptolensExamples`.

### CMake

There is a `CMakeLists.txt` in the root of the repository which can be used to build the library. The examples can
be built using the `CMakeLists.txt` in `examples/`.

The following commands, when ran from the root of the repository, builds the examples:
```
mkdir build
cd build
cmake ../examples
make
```

### GCC/Clang

The example file can also be build manually with GCC or Clang using the following command (run from the root of the repository):
```
gcc -Iinclude/ -Ithird_party/cJSON/ src/cryptolens.c src/data_object.c src/decode_base64.c src/error.c src/machine_code_computer_static.c src/request_handler_curl.c src/response_parser_cJSON.c src/signature_verifier_openssl.c third_party/cJSON/cJSON.c third_party/openbsd/base64.c third_party/openbsd/strlcpy.c -lcrypto -lssl -lcurl examples/example_activate.c
```
