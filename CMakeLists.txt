cmake_minimum_required(VERSION 3.18)
project(mlsec C CUDA)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CUDA_STANDARD 11)

# Enable CUDA
enable_language(CUDA)

# Find CUDA
find_package(CUDAToolkit REQUIRED)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${CUDAToolkit_INCLUDE_DIRS})

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O3")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -arch=sm_86")  # Adjust for your GPU

# Library source files
set(MLSEC_SOURCES
        src/io.c
        src/hashing.c
        src/matrix.c
        src/kmeans_cpu.c
        src/silhouette_cpu.c
        src/gpu/cuda/gpu_runtime_cuda.c
)

set(MLSEC_CUDA_SOURCES
        src/gpu/cuda/kmeans_kernels.cu
        src/gpu/cuda/silhouette_kernels.cu
        include/mlsec.h
        include/mlsec.h
        src/io.c
        tools/train.c
        src/hashing.c
        src/matrix.c
        src/kmeans_cpu.c
        src/silhouette_cpu.c
        src/gpu/cuda/gpu_runtime_cuda.c
        src/gpu/cuda/kmeans_kernels.cu
        src/gpu/cuda/silhouette_kernels.cu
        tools/eval.c
        tools/predict.c
        tests/test_hashing.c
)

# Create library
add_library(mlsec STATIC ${MLSEC_SOURCES} ${MLSEC_CUDA_SOURCES})
target_link_libraries(mlsec CUDA::cudart CUDA::cublas)

# Tools
add_executable(train tools/train.c)
target_link_libraries(train mlsec)

add_executable(eval tools/eval.c)
target_link_libraries(eval mlsec)

add_executable(predict tools/predict.c)
target_link_libraries(predict mlsec)

# Tests
enable_testing()
add_executable(test_hashing tests/test_hashing.c)
target_link_libraries(test_hashing mlsec)
add_test(NAME test_hashing COMMAND test_hashing)