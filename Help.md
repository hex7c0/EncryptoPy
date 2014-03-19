usage: encryptopy.py [-h] [-v] -p Path (-E | -D) [-r] [-c] [-s] [-d] [-f] [-t Threads] [-n Name] [-k Key ... ]  {module ... }

***

flag explanation:
* -h: show help _(info)_
* -v: show project version _(info)_

* -p: 'Path' of original file _(required)_
* -E or -D: for encryption of decryption _(required)_
* {'module' ... }: [aes,des,base,xor,...] type of work _(required)_

* -r: remove original file _(optional)_
* -c: compress file _(optional)_
* -s: print statistics and the end _(optional)_
* -d: set default key for module _(optional)_
* -f: force True on question mark _(optional)_
* -k: 'Key' size for some work; for chiper in row, use like this: '-k 32 256 4' _(optional)_
* -t: 'Threads' number of worker _(optional)_
* -n: 'Name' of new file _(optional)_


default flag:
* -n: original file with .cr extension
* -r: false
* -c: false
* -s: false
* -d: false
* -f: false

***

example:

<pre><code>python3 encryptopy.py -p pippo.pdf -E xor</code></pre>

create pippo.pdf.cr with xor encryption

<pre><code>python3 encryptopy.py -p pippo.pdf.cr -D xor -n ciao.pdf</code></pre>

create ciao.pdf with xor decryption, if password is correct

<pre><code>python3 encryptopy.py -r ciao.pdf -Ef hash -k 512</code></pre>

show sha512 hash and don't print question

<pre><code>python3 encryptopy.py -r ciao.pdf -E aes des -k 192 3</code></pre>

encrypt with aes192 first and triple_des after

<pre><code>python3 encryptopy.py -r ciao.pdf -Efcs otp crc -k 0 32</code></pre>

encryption in row, print statistic message after work, and compress original file