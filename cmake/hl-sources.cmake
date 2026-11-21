# HashLink's source lists, as absolute paths, for every build that compiles HashLink: this repository's CMakeLists.txt and
# hosts that compile the VM into their own library instead (Haxeon's Android host, android/app/src/main/cpp). A source
# added to HashLink is added here, once.
#
#   HL_JIT_AARCH64     ON when the AArch64 JIT backend is built (else x86 or x86-64)
#   HL_PCRE_SOURCES    the bundled PCRE2 (built with HAVE_CONFIG_H and PCRE2_STATIC, include/pcre on the include path)
#   HL_LIBHL_SOURCES   libhl: the GC, the profiler, number formatting and the standard library natives for this platform
#   HL_VM_SOURCES      the VM, less main.c: the bytecode loader, patching, the debugger, diagnostics and the profiler
#   HL_JIT_SOURCES     the JIT for this processor
#   HL_NO_JIT_SOURCES  in place of HL_JIT_SOURCES, the JIT's entry points for a VM without it, whose modules were compiled
#                      ahead of time (hl_module_init_aot)

set(_hl_root "${CMAKE_CURRENT_LIST_DIR}/..")
get_filename_component(_hl_root "${_hl_root}" ABSOLUTE)

# On macOS CMAKE_OSX_ARCHITECTURES decides (uname reports the host CPU, not the build CPU); elsewhere CMAKE_SYSTEM_PROCESSOR.
set(HL_JIT_AARCH64 OFF)
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64" AND NOT CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
        set(HL_JIT_AARCH64 ON)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(HL_JIT_AARCH64 ON)
endif()

set(HL_PCRE_SOURCES)
foreach(_name IN ITEMS auto_possess chartables compile config context convert dfa_match error extuni find_bracket
        jit_compile maketables match_data match newline ord2utf pattern_info script_run serialize string_utils study
        substitute substring tables ucd valid_utf xclass)
    list(APPEND HL_PCRE_SOURCES "${_hl_root}/include/pcre/pcre2_${_name}.c")
endforeach()

set(HL_LIBHL_SOURCES)
foreach(_source IN ITEMS gc.c prof.c ryu/d2s.c ryu/f2s.c
        std/array.c std/buffer.c std/bytes.c std/cast.c std/date.c std/debug.c std/error.c std/file.c std/fun.c
        std/maps.c std/math.c std/obj.c std/random.c std/regexp.c std/socket.c std/string.c std/sys.c std/track.c
        std/types.c std/ucs2.c std/thread.c std/process.c)
    list(APPEND HL_LIBHL_SOURCES "${_hl_root}/src/${_source}")
endforeach()
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    list(APPEND HL_LIBHL_SOURCES
        "${_hl_root}/include/mdbg/mdbg.c"
        "${_hl_root}/include/mdbg/mach_excServer.c"
        "${_hl_root}/include/mdbg/mach_excUser.c"
    )
endif()
if(ANDROID)
    list(APPEND HL_LIBHL_SOURCES "${_hl_root}/src/std/sys_android.c")
endif()
if(IOS_PLATFORM)
    list(APPEND HL_LIBHL_SOURCES "${_hl_root}/src/std/sys_ios.m")
endif()

set(HL_VM_SOURCES)
foreach(_source IN ITEMS src/code.c src/module.c src/hlpatch.c src/hlruntime.c src/debugger.c src/diagnostics.c
        src/diagnostics_transport.c src/profile.c src/prof_boundary.c include/lz4/lz4.c)
    list(APPEND HL_VM_SOURCES "${_hl_root}/${_source}")
endforeach()

set(HL_JIT_SOURCES)
if(HL_JIT_AARCH64)
    set(_hl_jit_backend jit_aarch64.c jit_aarch64_emit.c)
else()
    set(_hl_jit_backend jit_x86_64.c)
endif()
foreach(_source IN ITEMS jit.c jit_emit.c jit_regs.c ${_hl_jit_backend} jit_dump.c jit_gdb.c)
    list(APPEND HL_JIT_SOURCES "${_hl_root}/src/${_source}")
endforeach()

set(HL_NO_JIT_SOURCES "${_hl_root}/src/jit_none.c")
