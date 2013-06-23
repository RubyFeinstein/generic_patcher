#!python

from subprocess import check_call, STDOUT 
from os import unlink
import os
from os.path import exists
import struct

class BasePatch(object):
    def __init__(self, pos, data):
        self.pos = pos
        self.data = data
    
    def apply(self, firmware, **kargs):
        firmware += max(0, self.pos - len(firmware)) * "\x00"
        return firmware[:self.pos] + self.data + firmware[self.pos+len(self.data):]

class ArmPatch(BasePatch):
    def __init__(self, pos, lines, extra_data=""):
        self.pos = pos
        self.lines = lines
        self.extra_data = extra_data
    
    def _delete_temp(self,path):
        if exists(path):
            unlink(path)
    
    def _generate_bytes(self):
        try:
            temp_file = file('temp.asm','w')
            for i in self.lines:
                temp_file.write(i + "\n")
            temp_file.close()
            check_call("arm-elf-as -mthumb -o temp.o temp.asm", shell=True) 
            check_call("arm-elf-objcopy -O binary temp.o temp.bin", shell=True) 
            data = file('temp.bin','rb').read() + self.extra_data
            print "data_len: %d" % len(data)
            print "data: %s" % data.encode("hex")
            return data
        finally:
            self._delete_temp("temp.bin")
            self._delete_temp("temp.o")
            self._delete_temp("temp.asm")
    
    def get_bytes(self):
        return self._generate_bytes()
    
    def apply(self, firmware, **kargs):
        self.data = self._generate_bytes()
        return super(ArmPatch, self).apply(firmware)

class CPatch(BasePatch):
    def __init__(self, pos, filename, extra_data="", max_size=0xffffffff):
        self.pos = pos
        self.filename = filename
        self.extra_data = extra_data
        self.max_size = max_size
    
    def _delete_temp(self,path):
        if exists(path):
            unlink(path)
    
    def _generate_bytes(self, define):
        try:
            defines = " ".join(["-D%s=%s" % (i, define[i]) for i in define])
            check_call("arm-elf-gcc %s -Wno-multichar -nostdlib -mcpu=arm7tdmi -mthumb -fPIC -O1 -c -o temp.o %s" % (defines, self.filename), shell=True) 
            check_call("arm-elf-ld -EL -emy_start temp.o -o temp2.o", shell=True) 
            check_call("arm-elf-objcopy -O binary temp2.o temp.bin", shell=True) 
            data = file('temp.bin','rb').read() + self.extra_data
            print "generating: %s" % self.filename
            print "data_len: %d" % len(data)
            print "data: %s" % data.encode("hex")
            if(len(data) > self.max_size):
                raise Exception("detour on address 0x%08x size limit reached (%d > %d)" % (self.pos, len(data), self.max_size))
            return data
            
        finally:
            self._delete_temp("temp.bin")
            self._delete_temp("temp.o")
            self._delete_temp("temp2.o")
    
    def get_bytes(self):
        return self._generate_bytes()
    
    def apply(self, firmware, **kargs):
        define = kargs.get("define", {})
        self.data = self._generate_bytes(define)
        return super(CPatch, self).apply(firmware)
        
class TrapPatch(BasePatch):
    def __init__(self, pos):
        self.pos = pos
        
    def apply(self, firmware, **kargs):
        self.data = "00e8".decode("hex") # illegal opcode
        return super(TrapPatch, self).apply(firmware)        

class PutPatch(BasePatch):
    def __init__(self, pos, data):
        self.pos = pos
        self.data = data
        
        
class ReplacePatch(BasePatch):
    def __init__(self, search, replace):
        if len(search) != len(replace):
            raise Exception("len(search) != len(replace)")
        self.search = search
        self.replace = replace
        
    def apply(self, firmware, **kargs):
        self.data = "00e8".decode("hex") # illegal opcode
        return firmware.replace(self.search, self.replace)
        
class BLPatch(BasePatch):
    def __init__(self, pos, to):
        self.pos = pos
        self.data = self.patch_bl(pos, to)

    def patch_bl(self, src, dst):
        #patched_file = list(file(src_file, "rb").read())
        
        diff = dst - src - 4
        #print hex(diff)
        diff_upper = (diff >> 12) & 0x7ff
        diff_lower = (diff & 0xfff) >> 1
        a = (0xF000 | diff_upper)# << 16
        b = (0xF800 | diff_lower)
        c = (a << 16) | b
        print "patched: %X to call %X BL opcode: %X" % (src, dst, c)
        return struct.pack("<HH", a, b)        
        
def patch_firmware(src,dst, patchs, extra = "", **kargs):
    firmware = file(src,'rb').read()
    for p in patchs:
        firmware = p.apply(firmware, **kargs)
    firmware += extra
    firmware = file(dst,'wb').write(firmware)