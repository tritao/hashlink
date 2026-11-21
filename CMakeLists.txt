cmake_minimum_required(VERSION 3.13)

set(HL_VERSION_MAJOR 1)
set(HL_VERSION_MINOR 16)
set(HL_VERSION_PATCH 0)
set(HL_VERSION ${HL_VERSION_MAJOR}.${HL_VERSION_MINOR}.${HL_VERSION_PATCH})

cmake_policy(SET CMP0042 NEW)
if (${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.24)
	cmake_policy(VERSION 3.24)
endif()

if(WIN32)
    set(CMAKE_SYSTEM_VERSION 10.0)
endif()
project(hashlink)

include(GNUInstallDirs)
include(FindPkgConfig)
include(CTest)

set(WITH_VM_DEFAULT ON)
# The source lists and HL_JIT_AARCH64, shared with hosts that compile HashLink into their own library.
include(cmake/hl-sources.cmake)
# 32-bit ARM still has no JIT backend — fall back to disabling the VM there.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm$|^armv7" AND NOT HL_JIT_AARCH64)
    set(WITH_VM_DEFAULT OFF)
endif()

option(WITH_VM "Whether to build the Hashlink virtual machine" ${WITH_VM_DEFAULT})
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
if(BUILD_SHARED_LIBS)
    # ensure third-party static libs are built with PIC
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
if(ANDROID)
    set(_DOWNLOAD_DEPENDENCIES ON)
else()
    set(_DOWNLOAD_DEPENDENCIES OFF)
endif()
option(DOWNLOAD_DEPENDENCIES "Download & build third-party dependencies" ${_DOWNLOAD_DEPENDENCIES})
option(WITH_SYSTEM_PCRE2 "Link libhl against system installation of pcre2" OFF)
# One self-contained VM: libhl is an object library compiled into hl (and into the tools that link it), and hl exports
# the libhl API to the libraries it loads and resolves `std` primitives from itself. No libhl shared library is built.
option(HL_LIBHL_IN_VM "Compile libhl into the hl executable instead of linking it" OFF)

if(MSVC)
    if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set (CMAKE_INSTALL_PREFIX "C:/HaxeToolkit/hashlink" CACHE PATH "default install path" FORCE)
    endif()
endif()
option(FLAT_INSTALL_TREE "Flat install tree" ${MSVC})
if(FLAT_INSTALL_TREE)
    set(CMAKE_INSTALL_BINDIR .)
    set(CMAKE_INSTALL_LIBDIR .)
endif()
# force Unicode over Multi-byte
if(MSVC)
    add_definitions(-DUNICODE -D_UNICODE)
    add_compile_options(/permissive-)
endif()

if (MINGW)
    add_compile_options(-municode)
    add_link_options(-municode)
endif()

# hl_module_capture_stack walks the platform frame-pointer chain (module.c) to
# report accurate JIT stack traces; that walk starts from this runtime's own
# native frame, so it needs one too, regardless of what a given toolchain
# defaults to at this optimization level.
if(NOT MSVC)
    add_compile_options(-fno-omit-frame-pointer)
endif()

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/other/cmake
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_VISIBILITY_PRESET hidden)

# put output in "bin"

set(OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR})

# avoid the extra "Debug", "Release" directories
foreach( OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES} )
    string( TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG )
    set( CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${OUTPUT_DIR} )
    set( CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${OUTPUT_DIR} )
    set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${OUTPUT_DIR} )
endforeach()

if(HL_LIBHL_IN_VM)
    set(_libhl_kind OBJECT)
else()
    set(_libhl_kind "")
endif()
add_library(libhl ${_libhl_kind} ${HL_LIBHL_SOURCES})

target_include_directories(libhl
    PUBLIC src
)
if(HL_LIBHL_IN_VM)
    set_target_properties(libhl PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# C11 / C++11 are required for features such as unicode strings
target_compile_features(libhl PUBLIC cxx_std_11 c_std_11)

set(public_headers
    src/hl.h
    src/gc_write.h
    src/hl_ffi.h
    src/hlc.h
)

set_target_properties(libhl
    PROPERTIES
    PUBLIC_HEADER "${public_headers}"
)

if(MSVC)
    set_target_properties(libhl
        PROPERTIES
        OUTPUT_NAME libhl
    )
else()
    set_target_properties(libhl
        PROPERTIES
        OUTPUT_NAME hl
    )
endif()

set_target_properties(libhl
    PROPERTIES
    VERSION ${HL_VERSION}
    SOVERSION ${HL_VERSION_MAJOR}
    COMPILE_DEFINITIONS "_USRDLL;LIBHL_EXPORTS;PCRE2_CODE_UNIT_WIDTH=16"
)

if(WITH_SYSTEM_PCRE2)
    target_link_libraries(libhl pcre2-16)
else()
    target_sources(libhl PRIVATE ${HL_PCRE_SOURCES})
    target_include_directories(libhl PRIVATE include/pcre)
    target_compile_definitions(libhl PRIVATE HAVE_CONFIG_H PCRE2_STATIC)
endif()

if(APPLE)
    target_include_directories(libhl PRIVATE include)
endif()

if(WIN32)
    target_link_libraries(libhl ws2_32 user32 winmm)
else()
    target_link_libraries(libhl m dl)

    if(ANDROID)
        target_link_libraries(libhl log)
    else()
        target_link_libraries(libhl pthread)
    endif()
endif()

if (WITH_VM)
    if(NOT HL_JIT_AARCH64)
        string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" HL_VM_PROCESSOR)
        if(NOT HL_VM_PROCESSOR MATCHES "^(x86_64|amd64|i[3-6]86)$")
            message(FATAL_ERROR
                "The HashLink VM JIT supports only x86, x86-64, and AArch64 targets; "
                "configure with -DWITH_VM=OFF for ${CMAKE_SYSTEM_PROCESSOR}"
            )
        endif()
    endif()
    add_executable(hl ${HL_VM_SOURCES} ${HL_JIT_SOURCES} src/main.c)
    if(APPLE)
        set_target_properties(hl PROPERTIES
            INSTALL_RPATH "@executable_path;@executable_path/../${CMAKE_INSTALL_LIBDIR}"
        )
        if(HL_JIT_AARCH64)
            add_custom_command(TARGET hl POST_BUILD
                COMMAND codesign --force --sign - --entitlements
                    "${CMAKE_CURRENT_SOURCE_DIR}/other/osx/hl_jit.entitlements"
                    "$<TARGET_FILE:hl>"
                COMMENT "Signing hl with allow-jit entitlement"
            )
        endif()
        # On Apple Silicon, MAP_JIT pages require the binary to carry the
        # com.apple.security.cs.allow-jit entitlement. ad-hoc-sign with the
        # entitlement file shipped in other/osx/hl_jit.entitlements so a
        # freshly built `hl` can JIT without the user having to re-sign.
        if(HL_JIT_AARCH64)
            add_custom_command(TARGET hl POST_BUILD
                COMMAND codesign --force --sign - --entitlements
                    "${CMAKE_CURRENT_SOURCE_DIR}/other/osx/hl_jit.entitlements"
                    "$<TARGET_FILE:hl>"
                COMMENT "Signing hl with allow-jit entitlement"
            )
        endif()
    elseif (UNIX)
        set_target_properties(hl PROPERTIES
            INSTALL_RPATH "$ORIGIN;$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
        )
    endif()

    # The boundary hooks on Linux x86-64: their patcher, and the stubs and thunk (see src/prof_boundary_linux.c).
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        target_sources(hl PRIVATE src/prof_boundary_linux.c src/prof_boundary_x64_sysv.c)
    endif()

    # With HL_LIBHL_IN_VM, libhl is an object library: linking it puts all of its objects, compiled with LIBHL_EXPORTS,
    # into hl, which exports them.
    target_link_libraries(hl libhl)
    if(HL_LIBHL_IN_VM)
        target_compile_definitions(hl PRIVATE HL_LIBHL_IN_VM)
        set_target_properties(hl PROPERTIES ENABLE_EXPORTS ON)
    endif()

    if (WIN32)
        target_link_libraries(hl user32 dbghelp)
    endif()
    # MinGW gives an executable an import library too, named libhl.dll.a like libhl's: relinking hl would overwrite the
    # one it links against.
    if (MINGW)
        set_target_properties(hl PROPERTIES IMPORT_SUFFIX ".exe.a")
    endif()
endif()

# The function hooks linked into natively instrumented modules on Linux (see src/prof_hooks.c). Position independent, as
# they end up in shared objects; their symbols are hidden, so each module calls its own copy.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(hlprof_hooks STATIC src/prof_hooks.c)
    set_target_properties(hlprof_hooks PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(hlprof_hooks PRIVATE -fvisibility=hidden)
endif()

# The /Gh /GH hooks linked into natively instrumented modules (see src/prof_penter.c). They use no C runtime, so
# modules built with either CRT link them.
if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    enable_language(ASM_MASM)
    add_library(hlprof_penter STATIC src/prof_penter.c src/prof_penter_x64.asm)
    target_compile_options(hlprof_penter PRIVATE $<$<COMPILE_LANGUAGE:C>:/Zl /GS->)
    # The boundary hooks' common thunk (see src/prof_boundary.c).
    if(TARGET hl)
        target_sources(hl PRIVATE src/prof_boundary_x64.asm)
        target_link_libraries(hl dxguid)
    endif()
endif()

# Measures the profiler recorder's cost per record (see tools/hlprof-bench.c).
add_executable(hlprof-bench tools/hlprof-bench.c)
target_link_libraries(hlprof-bench PRIVATE libhl)

add_executable(hlprof-live tools/hlprof-live.c tools/pftrace.c tools/elf_symbols.c include/lz4/lz4.c)
if(WIN32)
    target_link_libraries(hlprof-live PRIVATE ws2_32)
else()
    # dlopen, for the C++ demangler (part of libc from glibc 2.34).
    target_link_libraries(hlprof-live PRIVATE ${CMAKE_DL_LIBS})
endif()

# Prints a bytecode file as text, for diffing builds (see tools/hldump.c). It reads with the VM's own reader.
add_executable(hldump tools/hldump.c src/code.c)
target_include_directories(hldump PRIVATE src)
target_link_libraries(hldump PRIVATE libhl)

if(BUILD_TESTING)

    find_program(
        HAXE_COMPILER
        haxe
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        SET(HAXE_HL_FLAGS -D hl-legacy32)
    endif()

    if(MINGW)
        set(HLC_LIBRARIES dbghelp)
    endif()

    #####################
    # hello.hl

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello.hl
        COMMAND ${HAXE_COMPILER}
            ${HAXE_HL_FLAGS}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello.hl
            -cp ${CMAKE_SOURCE_DIR}/other/tests -main HelloWorld
    )
    add_custom_target(hello.hl ALL
        DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello.hl
    )

    #####################
    # threads.hl

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads.hl
        COMMAND ${HAXE_COMPILER}
            ${HAXE_HL_FLAGS}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads.hl
            -cp ${CMAKE_SOURCE_DIR}/other/tests -main Threads
    )
    add_custom_target(threads.hl ALL
        DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads.hl
    )

    #####################
    # uvsample.hl

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample.hl
        COMMAND ${HAXE_COMPILER}
            ${HAXE_HL_FLAGS}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample.hl
            -cp ${CMAKE_SOURCE_DIR}/other/uvsample -main UVSample
    )
    add_custom_target(uvsample.hl ALL
        DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample.hl
    )

    #####################
    # hello.c

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello/hello.c
        COMMAND ${HAXE_COMPILER}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello/hello.c
            -cp ${CMAKE_SOURCE_DIR}/other/tests -main HelloWorld
    )
    add_executable(hello
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello/hello.c
    )
    set_target_properties(hello
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello
    )
    target_include_directories(hello
        PRIVATE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello
    )
    target_link_libraries(hello
        libhl
        ${HLC_LIBRARIES}
    )

    #####################
    # threads.c

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads/threads.c
        COMMAND ${HAXE_COMPILER}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads/threads.c
            -cp ${CMAKE_SOURCE_DIR}/other/tests -main Threads
    )
    add_executable(threads
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads/threads.c
    )
    set_target_properties(threads
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads
    )
    target_include_directories(threads
        PRIVATE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads
    )
    target_link_libraries(threads
        libhl
        ${HLC_LIBRARIES}
    )

    #####################
    # uvsample.c

    add_custom_command(OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample/uvsample.c
        COMMAND ${HAXE_COMPILER}
            -hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample/uvsample.c
            -cp ${CMAKE_SOURCE_DIR}/other/uvsample -main UVSample
    )
    add_executable(uvsample
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample/uvsample.c
    )
    set_target_properties(uvsample
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample
    )
    target_include_directories(uvsample
        PRIVATE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample
    )
    target_link_libraries(uvsample
        libhl
        uv.hdll
        ${HLC_LIBRARIES}
    )

    #####################
    # header_macro_clashes.c

    add_executable(header_macro_clashes
        ${CMAKE_SOURCE_DIR}/other/tests/header_macro_clashes/header_macro_clashes.c
    )
    set_target_properties(header_macro_clashes
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/
    )
    target_link_libraries(header_macro_clashes
        libhl
        ${HLC_LIBRARIES}
    )

    #####################
    # Tests
    if (WITH_VM)
        add_test(NAME version
            COMMAND hl --version
        )
        set_tests_properties(version
            PROPERTIES
            PASS_REGULAR_EXPRESSION "${HL_VERSION}"
        )

        add_test(NAME hello.hl
            COMMAND hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/hello.hl
        )
        add_test(NAME threads.hl
            COMMAND hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/threads.hl
        )
        add_test(NAME uvsample.hl
            COMMAND hl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test/uvsample.hl 6001
        )
    endif()

    add_test(NAME hello
        COMMAND hello
    )
    add_test(NAME threads
        COMMAND threads
    )
    add_test(NAME uvsample
        COMMAND uvsample 6002
    )
endif()

#####################
# Packaging

set(CPACK_OUTPUT_FILE_PREFIX ${OUTPUT_DIR})

set(CPACK_PACKAGE_VENDOR "Haxe Foundation")
set(CPACK_PACKAGE_VERSION_MAJOR ${HL_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${HL_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${HL_VERSION_PATCH})

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()

set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

set(HDLL_DESTINATION
    ${CMAKE_INSTALL_LIBDIR}
)

set(INSTALL_TARGETS libhl hlprof-live)
if (WITH_VM)
    list(APPEND INSTALL_TARGETS hl)
endif()

install(
    TARGETS
        ${INSTALL_TARGETS}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
    FILES src/hlc_main.c
    TYPE INCLUDE
)

# uninstall target
# https://gitlab.kitware.com/cmake/community/wikis/FAQ#can-i-do-make-uninstall-with-cmake
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/other/cmake/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()


if(
    NOT DEFINED ENV{APPVEYOR_REPO_TAG_NAME}
    AND
    DEFINED ENV{APPVEYOR_REPO_COMMIT}
)
    string(SUBSTRING $ENV{APPVEYOR_REPO_COMMIT} 0 7 short_commit)
endif()

if(NOT DEFINED ENV{TRAVIS_TAG} AND DEFINED ENV{TRAVIS_COMMIT})
    string(SUBSTRING $ENV{TRAVIS_COMMIT} 0 7 short_commit)
endif()

if(DEFINED short_commit)
    set(CPACK_PACKAGE_VERSION "${HL_VERSION}+${short_commit}")
endif()


include(CPack)

add_subdirectory(libs)
