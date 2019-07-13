#Copyright © 2019, dex (https://devel0pment.de/?p=1210)

#!/usr/bin/env python
 
from pwn import *
import gmpy
 
n = 26507591511689883990023896389022361811173033984051016489514421457013639621509962613332324662222154683066173937658495362448733162728817642341239457485221865493926211958117034923747221236176204216845182311004742474549095130306550623190917480615151093941494688906907516349433681015204941620716162038586590895058816430264415335805881575305773073358135217732591500750773744464142282514963376379623449776844046465746330691788777566563856886778143019387464133144867446731438967247646981498812182658347753229511846953659235528803754112114516623201792727787856347729085966824435377279429992530935232902223909659507613583396967
e = 65537
 
m = int('cat flag'.encode('hex'), 16)
 
# suitable blinding factor
r = 6631
 
# calculate modified message m1
m1 = (m*r**e)%n
m1 = hex(m1)[2:] # cut leading '0x'
if (len(m1)%2 == 1): m1 = '0' + m1 # adjust padding
m1 = m1.decode('hex').encode('base64').replace('\n','') # encode
 
# connect to ctf server
p = remote('blind.q.2019.volgactf.ru', 7070)
p.recvuntil('Enter your command')
 
# sign modified message m1
p.sendline('1 sign')
p.recvuntil('Enter your command to sign:')
p.sendline(m1)
 
# receive signature s1
p.recvline()
resp = p.recvline()
s1 = int(resp)
 
# calculate signature s from s1 and r
s = s1*int(gmpy.invert(r,n))%n
 
# send command 'cat flag' with appropriate signature
p.sendline(str(s) + ' cat flag')
p.interactive()