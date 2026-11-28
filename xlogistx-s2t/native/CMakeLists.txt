# Standalone whisper DLL for the XlogistX speech-to-text module.
#
# Builds libwhisper.dll with everything it can carry linked inside it:
#   - whisper.cpp and ggml are compiled as static libraries and linked in
#   - libstdc++ and libgcc are linked statically
#   - exported: the xs2t_* shim functions (xs2t_shim.c) used by Java, plus the whisper_* C API
#
# One runtime file still ships beside it: libwinpthread-1.dll.
# CLion's bundled MinGW builds winpthread against the UCRT while the rest of
# the toolchain uses msvcrt, so its static libpthread.a does not link here
# (undefined __intrinsic_setjmpex). The DLL form is the combination the
# toolchain itself uses, so that is what we link against.
#
# Source: ./whisper.cpp (git clone of https://github.com/ggml-org/whisper.cpp at a pinned tag)

cmake_minimum_required(VERSION 3.24)
project(Whisper C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# whisper.cpp / ggml build options
set(BUILD_SHARED_LIBS      OFF CACHE BOOL "" FORCE)   # static archives, linked into our DLL below
set(WHISPER_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WHISPER_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(WHISPER_BUILD_SERVER   OFF CACHE BOOL "" FORCE)
set(GGML_OPENMP            OFF CACHE BOOL "" FORCE)   # no libgomp dependency

# ON  = tuned to the CPU of the build machine (fastest here, may crash on other CPUs)
# OFF = portable x86-64 build with AVX, AVX2, FMA, F16C, BMI2 and no AVX-512
option(WHISPER_STANDALONE_NATIVE "Optimize for the build machine's CPU" OFF)
set(GGML_NATIVE ${WHISPER_STANDALONE_NATIVE} CACHE BOOL "" FORCE)

# Portable build: pin the instruction sets explicitly, so the result does not
# depend on the build machine or on values left in the CMake cache.
if (NOT WHISPER_STANDALONE_NATIVE)
    foreach (opt GGML_SSE42 GGML_AVX GGML_AVX2 GGML_BMI2 GGML_FMA GGML_F16C)
        set(${opt} ON CACHE BOOL "" FORCE)
    endforeach ()
    foreach (opt GGML_AVX_VNNI GGML_AVX512 GGML_AVX512_VBMI GGML_AVX512_VNNI GGML_AVX512_BF16)
        set(${opt} OFF CACHE BOOL "" FORCE)
    endforeach ()
endif ()

add_subdirectory(whisper.cpp EXCLUDE_FROM_ALL)

# Mark the whisper_* API as dllexport inside the static library, so the
# symbols are exported when the archive is linked whole into our DLL.
target_compile_definitions(whisper PRIVATE WHISPER_SHARED WHISPER_BUILD)

# xs2t_shim.c is the C surface the Java module binds; see the comment at its top.
add_library(whisper_standalone SHARED xs2t_shim.c)
target_include_directories(whisper_standalone PRIVATE
        whisper.cpp/include
        whisper.cpp/ggml/include)
set_target_properties(whisper_standalone PROPERTIES
        PREFIX "lib"
        OUTPUT_NAME "whisper"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(whisper_standalone PRIVATE
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,whisper>")

if (MINGW)
    target_link_options(whisper_standalone PRIVATE
            -static-libgcc -static-libstdc++)
endif ()
