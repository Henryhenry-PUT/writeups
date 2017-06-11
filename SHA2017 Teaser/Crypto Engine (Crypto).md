# Intro

![alttext](img/flag.png "flag")


First we notice that color square is added for every three letters in text to encrypt. At the end of image we have `n mod 3` two-decimal hex numbers. Also, color of previous squares didn't change if we add more letters. Knowing that the flag must be in format `flag{md5hash}` we have tried encrypt `flag{x`


![alttext](img/flagx.png "'flag{x'")


And we get what we want to. RGB code of the first color was exactly the same as the color of the flag, and also second color had only different blue value in comprasion with the flag. So, it's brute force time!

# Preparing

First, We prepared code for downloading image and changing it to the color values. Every square is 40x40 with some border, so we take pixel at `(5, 20)`. Also, we didn't analyze the text on the flag, we now that the last character must be `}`, so it will leave us only one character to guess. Here code comes!

```
from PIL import Image
import requests
import numpy as np

def download_img(url):
    img = Image.open(requests.get(url, stream=True).raw)
    img = np.array(img.getdata())
    img = np.resize(img, (40, int(len(img)/40), 3))
    return img

def img_to_code(url):
    img = download_img(url)
    length = len(img[0])
    column = 20
    array = []
    while column < length:
        for i in img[5][column]:
            array.append(i)
        column = column + 40
    return array
```

# Brute force

We now that the flag is in the `flag{md5hash}` format, so we only have to brute force values in `[a-fA-F0-9]`. To get new square encrypted text must be multiplication of 3. This leaded to not-so-beautiful `if` statement in our solution, but *it works* :D

```
flag_url = "https://cryptoengine.stillhackinganyway.nl/flag"
flag = img_to_code(flag_url)
print(flag)

url = "https://cryptoengine.stillhackinganyway.nl/encrypt?text="
text = "fla"

enc_text = img_to_code(url+text)
possible = "abcdefABCDEF0123456789"

while len(enc_text) < len(flag):
    len_enc = len(enc_text)
    cur_three = ""
    start = 0
    if(text == "fla"):
        cur_three = "g{"
        start = 2
    for i in range(start, 3):
        for x in possible:
            temp = cur_three + x #guess next letter
            temp = temp + "a"*(3-len(temp)) #fill to three letters
            temp_url = url+text+temp #concatenate url
            print(temp_url)
            attempt = img_to_code(temp_url)
            if attempt[len_enc+i] == flag[len_enc+i]: #if guess is correct
                cur_three = cur_three + x
                break
    text = text + cur_three
    enc_text = img_to_code(url+text)
```


![alttext](img/flagalmost.png "flag from our algorithm")


# Get the flag
After that we bruteforced by hand last char of md5hash and get the flag! `flag{deaf983eb34e485ce9d2aff0ae44f852}`


--
maverick, **PUT CTF team**
