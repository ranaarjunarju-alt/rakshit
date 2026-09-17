#!/usr/bin/env python3
"""
dex_core.py — minimal pure-Python DEX (035) builder.

Only the bytecode subset needed for the RE logger is implemented.
Every section is emitted in spec order & sorting; a structural self-check
re-decodes the final file before it is written.
"""
import hashlib, struct, zlib

NO_INDEX = 0xFFFFFFFF

# ------------------------------------------------------------------ leb128
def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        done = (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40))
        if done:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)

# ------------------------------------------------------------------ symbols
class Dex:
    def __init__(self):
        self.str_list = []                 # ordered unique strings
        self.str_map = {}
        self.type_map = {}                 # desc -> 't' token resolved later
        self.protos = []                   # (ret, (params...))
        self.proto_map = {}
        self.fields = []                   # (cls, name, desc)
        self.field_map = {}
        self.methods = []                  # (cls, name, ret, params)
        self.method_map = {}
        self.classes = []

    def sid(self, s):
        if s not in self.str_map:
            self.str_map[s] = len(self.str_list)
            self.str_list.append(s)
        return ('s', s)

    def tid(self, desc):
        self.sid(desc)
        self.type_map.setdefault(desc, True)
        return ('t', desc)

    def proto(self, ret, params):
        self.tid(ret)
        for p in params:
            self.tid(p)
        shorty = self._shorty(ret) + ''.join(self._shorty(p) for p in params)
        key = (ret, tuple(params), shorty)
        if key not in self.proto_map:
            self.proto_map[key] = len(self.protos)
            self.protos.append(key)
        return ('p', key)

    @staticmethod
    def _shorty(d):
        return 'L' if d.startswith('L') or d.startswith('[') else d[0]

    def fid(self, cls, name, desc):
        self.tid(cls); self.sid(name); self.tid(desc)
        k = (cls, name, desc)
        if k not in self.field_map:
            self.field_map[k] = len(self.fields)
            self.fields.append(k)
        return ('f', k)

    def mid(self, cls, name, ret, params):
        self.tid(cls); self.sid(name); self.proto(ret, params)
        k = (cls, name, ret, tuple(params))
        if k not in self.method_map:
            self.method_map[k] = len(self.methods)
            self.methods.append(k)
        return ('m', k)

    def add_class(self, desc, access, super_desc, interfaces, statics, instances,
                  directs, virtuals):
        self.tid(desc)
        if super_desc:
            self.tid(super_desc)
        for i in interfaces:
            self.tid(i)
        self.classes.append(dict(desc=desc, access=access, super=super_desc,
                                 interfaces=interfaces, statics=statics,
                                 instances=instances, directs=directs,
                                 virtuals=virtuals))

# ------------------------------------------------------------------ asm
class Asm:
    def __init__(self):
        self.items = []            # ('label',name) | ('insn',[tokens]) | ('try',(begin,end,handler,tdesc|None))
        self.n = 0                 # units so far

    def L(self, name):
        self.items.append(('label', name)); return self

    def raw(self, units):
        for u in units:
            assert isinstance(u, tuple) or (0 <= u <= 0xFFFF)
        self.items.append(('insn', list(units)))
        self.n += len(units)
        return self

    # ---- 11x
    def move_result(self, r):         return self.raw([0x0a | r << 8])
    def move_result_wide(self, r):    return self.raw([0x0b | r << 8])
    def move_result_object(self, r):  return self.raw([0x0c | r << 8])
    def move_exception(self, r):      return self.raw([0x0d | r << 8])
    def ret_void(self):               return self.raw([0x0e])
    def ret(self, r):                 return self.raw([0x0f | r << 8])
    def ret_wide(self, r):            return self.raw([0x10 | r << 8])
    def ret_object(self, r):          return self.raw([0x11 | r << 8])
    def monitor_enter(self, r):       return self.raw([0x1d | r << 8])
    def monitor_exit(self, r):        return self.raw([0x1e | r << 8])
    def throw(self, r):               return self.raw([0x27 | r << 8])

    # ---- 12x
    def move(self, a, b):             return self.raw([0x01 | a << 8 | b << 12])
    def move_wide(self, a, b):        return self.raw([0x04 | a << 8 | b << 12])
    def move_object(self, a, b):      return self.raw([0x07 | a << 8 | b << 12])
    def array_length(self, a, b):     return self.raw([0x21 | a << 8 | b << 12])
    def cmp_long(self, a, b, c):      return self.raw([0x31 | a << 8, b | c << 8])
    def add_long_2(self, a, b):       return self.raw([0xbb | a << 8 | b << 12])
    def sub_long_2(self, a, b):       return self.raw([0xbc | a << 8 | b << 12])
    def int_to_long(self, a, b):      return self.raw([0x81 | a << 8 | b << 12])
    def neg_long(self, a, b):         return self.raw([0x7d | a << 8 | b << 12])

    # ---- 11n / 21s / 31i / wide
    def const4(self, r, v):           return self.raw([0x12 | r << 8 | (v & 0xF) << 12])
    def const16(self, r, v):          return self.raw([0x13 | r << 8, v & 0xFFFF])
    def constw16(self, r, v):         return self.raw([0x16 | r << 8, v & 0xFFFF])
    def constw32(self, r, v):
        v &= 0xFFFFFFFF
        return self.raw([0x17 | r << 8, v & 0xFFFF, v >> 16 & 0xFFFF])

    def const32(self, r, v):
        v &= 0xFFFFFFFF
        return self.raw([0x14 | r << 8, v & 0xFFFF, v >> 16 & 0xFFFF])

    # ---- 21c (string/type/static-field)
    def const_string(self, r, sref):  return self.raw([0x1a | r << 8, ('s', sref)])
    def check_cast(self, r, tref):    return self.raw([0x1f | r << 8, ('t', tref)])
    def new_instance(self, r, tref):  return self.raw([0x22 | r << 8, ('t', tref)])
    def sget(self, r, fref):          return self.raw([0x60 | r << 8, ('f', fref)])
    def sget_wide(self, r, fref):     return self.raw([0x61 | r << 8, ('f', fref)])
    def sget_object(self, r, fref):   return self.raw([0x62 | r << 8, ('f', fref)])
    def sget_boolean(self, r, fref):  return self.raw([0x63 | r << 8, ('f', fref)])
    def sput(self, r, fref):          return self.raw([0x67 | r << 8, ('f', fref)])
    def sput_wide(self, r, fref):     return self.raw([0x68 | r << 8, ('f', fref)])
    def sput_object(self, r, fref):   return self.raw([0x69 | r << 8, ('f', fref)])

    # ---- 22c (instance field / arrays)
    def iget(self, r, o, fref):       return self.raw([0x52 | r << 8 | o << 12, ('f', fref)])
    def iget_object(self, r, o, fref):return self.raw([0x54 | r << 8 | o << 12, ('f', fref)])
    def iput(self, r, o, fref):       return self.raw([0x59 | r << 8 | o << 12, ('f', fref)])
    def iput_object(self, r, o, fref):return self.raw([0x5b | r << 8 | o << 12, ('f', fref)])
    def new_array(self, r, c, tref):  return self.raw([0x23 | r << 8 | c << 12, ('t', tref)])
    def instance_of(self, r, c, tref):return self.raw([0x20 | r << 8 | c << 12, ('t', tref)])

    # ---- 23x / 22b
    def aget_object(self, a, b, c):   return self.raw([0x46 | a << 8, b | c << 8])
    def aput_object(self, a, b, c):   return self.raw([0x4d | a << 8, b | c << 8])
    def add_int_lit8(self, a, b, v):  return self.raw([0xd8 | a << 8, b | (v & 0xFF) << 8])
    def sub_long(self, a, b, c):      return self.raw([0x9c | a << 8, b | c << 8])

    # ---- branches
    def goto(self, lab):              return self.raw([('g8', lab)])
    def if_eqz(self, r, lab):         return self.raw([0x38 | r << 8, ('rel', lab)])
    def if_nez(self, r, lab):         return self.raw([0x39 | r << 8, ('rel', lab)])
    def if_gez(self, r, lab):         return self.raw([0x3b | r << 8, ('rel', lab)])
    def if_lt(self, a, b, lab):       return self.raw([0x34 | a << 8 | b << 12, ('rel', lab)])
    def if_ge(self, a, b, lab):       return self.raw([0x35 | a << 8 | b << 12, ('rel', lab)])

    # ---- invokes
    def _inv(self, op, mref, regs):
        n = len(regs)
        if n <= 5:
            r = list(regs) + [0] * (5 - n)
            self.raw([op | n << 12, ('m', mref),
                      r[0] | r[1] << 4 | r[2] << 8 | r[3] << 12 | r[4] << 16])
        else:
            raise ValueError('too many regs; use _inv_range with contiguous regs')
        return self

    def _inv_range(self, op, mref, start, cnt):
        self.raw([op | cnt << 12, ('m', mref), start])
        return self

    def inv_virtual(self, mref, *regs):   return self._inv(0x6e, mref, regs)
    def inv_super(self, mref, *regs):     return self._inv(0x6f, mref, regs)
    def inv_direct(self, mref, *regs):    return self._inv(0x70, mref, regs)
    def inv_static(self, mref, *regs):    return self._inv(0x71, mref, regs)
    def inv_interface(self, mref, *regs): return self._inv(0x72, mref, regs)
    def inv_virtual_range(self, mref, start, cnt):  return self._inv_range(0x74, mref, start, cnt)
    def inv_direct_range(self, mref, start, cnt):   return self._inv_range(0x76, mref, start, cnt)
    def inv_static_range(self, mref, start, cnt):   return self._inv_range(0x77, mref, start, cnt)

    def try_catch_all(self, begin, end, handler):
        self.items.append(('try', (begin, end, handler, None)))
        return self

    def try_catch(self, begin, end, handler, tdesc):
        self.items.append(('try', (begin, end, handler, tdesc)))
        return self
