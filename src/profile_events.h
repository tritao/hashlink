#ifndef HL_PROFILE_EVENTS_H
#define HL_PROFILE_EVENTS_H

/* HashLink profiler event IDs. Span payloads are UTF-8 names without a terminator.
   A begin/end pair must have the same name and thread ID. Keep haxeon.ProfileSpan's
   constants in sync with PROFILE_EVENT_SPAN_BEGIN and PROFILE_EVENT_SPAN_END. */
#define PROFILE_EVENT_MODULE_REVISION 0x484C0001U
#define PROFILE_EVENT_THREAD_NAME 0x484C0002U
#define PROFILE_EVENT_GC_STATS 0x484C0003U
#define PROFILE_EVENT_NATIVE_SYMBOL 0x484C0004U
#define PROFILE_EVENT_ALLOCATION_SAMPLE 0x484C0005U
/* Follows a NATIVE_SYMBOL for the same pc: u64 pc, u64 module base, u64 module size (0 if unknown), u32 line (0 if
   unknown), u32 file length, then the UTF-8 source file. */
#define PROFILE_EVENT_NATIVE_LOCATION 0x484C0006U
/* A module was registered (u64 module id): its code is new to symbol metadata a client already holds. */
#define PROFILE_EVENT_MODULE_LOADED 0x484C0007U
/* Recording paused (u32 0) or resumed (u32 1) within a session. A pause is written before recording stops and a resume
   after it starts, so the calls between them went unrecorded. */
#define PROFILE_EVENT_RECORDING 0x484C0008U
/* Calls dropped for being shorter than the session's minimum call duration, counted on one thread since its last such
   event: entries of u64 call key, u32 count, u32 0. */
#define PROFILE_EVENT_DROPPED_CALLS 0x484C0009U
/* The runtime's startup before the program's entry point, written once when the first session starts before it: u32
   thread, u32 count, then per phase u64 begin and u64 end ticks (relative to the session's base, which is the first
   phase's start), u32 name length, u32 0, and the UTF-8 name padded to 8 bytes. */
#define PROFILE_EVENT_STARTUP 0x484C000AU
#define PROFILE_EVENT_SPAN_BEGIN 0x484C1001U
#define PROFILE_EVENT_SPAN_END 0x484C1002U
/* A program-defined counter sample: f64 value, then the UTF-8 counter name. Keep haxeon.ProfileCounter in sync. */
#define PROFILE_EVENT_COUNTER 0x484C1003U

#endif
