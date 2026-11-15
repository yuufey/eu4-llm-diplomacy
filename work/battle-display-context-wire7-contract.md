# IBOW v7 display-context extension, batch74

Fixed EXE b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77.
This is a value-only same-event snapshot of shared client definitions and
literal localization. It does not establish a rendered popup, observer
knowledge, or complete B04 text. Existing v6 native Line1 remains distinct.

All integers little-endian. Outer frame: `IBOW`, u16=7, u32 length, unchanged
complete v6 frame, `DCTX`, u16 extension version=1, u32 body length, body.
No trailing bytes. Max entire frame 512 KiB; max extension arena 32768 bytes.

Body fixed 27 bytes: context_state u8 (0 unknown/1 observed), capture_stage u8
(1/2/3; current producer uses 3 router_scope_exit), failure u16 (0..9),
sequence u64, raw_date i32, battle_kind u8 (1 land/2 naval), popup_kind_raw i32,
layout_raw i32, button_flag_raw u8, entry_count u8=7.

Then seven entries, strictly IDs 1..7 in order. Each: field_id u8, field_state
u8 (0 unknown/1 observed/2 absent), reserved u16=0, byte_length u32, raw bytes.
Names: definition_key, language, body_template, button1, button2, button3,
compact_losses_template. Limits respectively 64,256,8192,8192,8192,8192,8192.
No embedded NUL; sum lengths <=32768. Empty observed text is distinct from
unknown/absent, which require zero bytes. Language is ASCII `l_` followed by
one or more ASCII letters/digits/underscore. Definition key must exactly equal
LANDBATTLEOVER/NAVALBATTLEOVER according to battle_kind. The first two fields
must be observed for an observed context. Other fields may be unknown/absent;
cache absence does not prove widget absence/hidden state.

Unknown context: stage/sequence/date/kind/scalars zero, failure 1..9, all seven
entries unknown and empty. Failure IDs follow display-context-layout.h.
Observed context: failure0, sequence>0, kind1/2, stage1..3. Dates/scalars retain
raw signed values; popup_kind_raw is dynamic and may be0 or differ from kind.
Snapshot arena is packed in field order; no pointers or native header padding
are serialized. C++ validity rules live in the root-owned layout header.

The decoder dispatches v1..v6 unchanged through the existing v6 decoder and
adds wire7/display_context only for v7. Syntax/bounds errors reject v7. The
public local context projection additionally checks sequence/date/kind against
the embedded actual v6 observation; mismatches retract this local projection,
not the valid embedded world battle. It retains raw bytes on codec failure,
and always sets full_display_complete/runtime_popup_verified/visibility_verified
false. It never substitutes current settings into historical records.

The actual producer captures once at router scope exit, before slot_ready,
with scope/sequence/kind/date and outer process/player/code guards. Pure reads
only, no native lookup/fallback/setter/formatter/UI call. Definition and locale
graphs must be stable across two complete bounded passes. Failure clears the
context but retains the existing v6 battle data. Capture before/after identity
and ambiguity/drop rules remain under observer ownership.
