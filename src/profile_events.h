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
#define PROFILE_EVENT_SPAN_BEGIN 0x484C1001U
#define PROFILE_EVENT_SPAN_END 0x484C1002U

#endif
