cmake_minimum_required (VERSION 3.0.2)
project (cryptolens_examples)

add_subdirectory ("../" "cryptolens-c")

add_executable(example_external_activate example_external_activate.c)
target_link_libraries(example_external_activate cryptolens)

add_executable(example_data_object example_data_object.c)
target_link_libraries(example_data_object cryptolens)
target_link_libraries(example_data_object curl crypto ssl)

add_executable(example_activate example_activate.c)
target_link_libraries(example_activate cryptolens)
target_link_libraries(example_activate curl crypto ssl)
