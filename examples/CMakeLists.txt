cmake_minimum_required (VERSION 3.0.2)
project (cryptolens_examples)

add_subdirectory ("../" "cryptolens-c")


add_executable(example_external_activate example_external_activate.c)
target_link_libraries(example_external_activate cryptolens)
