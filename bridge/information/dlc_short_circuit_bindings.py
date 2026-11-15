"""B23 single-bit DLC bindings from retained REA names and predicate bytes."""

DLC_OVERRIDE_RVA = 0x233FEB6
DLC_BINDINGS = {
    0x1: ('Conquest of Paradise', 0x233FF40),
    0x2: ('Wealth of Nations', 0x233FF30),
    0x4: ('Res Publica', 0x233FEB4),
    0x8: ('Art of War', 0x233FF74),
    0x10: ('El Dorado', 0x233FF44),
    0x20: ('Common Sense', 0x233FF20),
    0x40: ('The Cossacks', 0x233FF10),
    0x80: ('Mare Nostrum', 0x233FF1C),
    0x100: ('Rights of Man', 0x233FF00),
    0x200: ('Mandate of Heaven', 0x233FF0C),
    0x400: ('Third Rome', 0x233FF08),
    0x800: ('Cradle of Civilization', 0x233FF04),
    0x1000: ('Rule Britannia', 0x233FF18),
    0x2000: ('Dharma', 0x233FF78),
    0x4000: ('Golden Century', 0x233FF14),
    0x8000: ('Emperor', 0x233FF24),
    0x10000: ('Leviathan', 0x233FF28),
    0x20000: ('Origins', 0x233FF2C),
    0x40000: ('Lions of the North', 0x233FF54),
    0x80000: ('Domination', 0x233FF6C),
    0x100000: ('King of Kings', 0x233FF50),
    0x200000: ('Winds of Change', 0x233FF70),
    0x400000: ('American Dream', 0x233FF34),
    0x800000: ('Purple Phoenix', 0x233FF3C),
    0x1000000: ('Star and Crescent', 0x233FF38),
    0x2000000: ('Women in History', 0x233FF48),
    0x4000000: ('Muslim Advisor Portraits', 0x233FF68),
    0x8000000: ('National Monuments', 0x233FF64),
    0x10000000: ('National Monuments II', 0x233FF60),
    0x20000000: ('Dharma - Indian Sultanate Pack', 0x233FF5C),
    0x40000000: ('Dharma - Hindu Unit Pack', 0x233FF58),
}

SUPPORTED_DLC_NAMES = tuple(name for name, _rva in DLC_BINDINGS.values())
