"""Remote solver: leak A via multi_hash, run BKZ in <190s, submit."""
import os, sys, socket, ssl, time, re
import numpy as np
from fpylll import IntegerMatrix, BKZ, LLL
from sympy import Matrix

HOST = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
N, M, Q = 64, 164, 12289
STRAT = "/usr/local/Cellar/fplll/5.5.0/share/fplll/strategies/default.json"
assert os.path.exists(STRAT), "BKZ strategies file not found"
STRAT_BYTES = STRAT.encode()
T0 = time.time()
def log(msg): print(f"[{time.time()-T0:6.1f}s] {msg}", file=sys.stderr, flush=True)

def connect(host, port):
    raw = socket.create_connection((host, port))
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 15)
    except Exception:
        pass
    try:
        raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', 4), 15)
        raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', 5), 5)
        raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', 6), 6)
    except Exception:
        pass
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    return sock

sock = connect(HOST, PORT)
io = sock.makefile("rwb")
def write(s):
    io.write(s.encode()); io.flush()

def expect_until(needle):
    buf = b""
    while needle not in buf:
        ch = io.read(1)
        if not ch: return None
        buf += ch
    return buf

# Read flag_hash
buf = expect_until(b"Your choice: ")
text = buf.decode(errors='replace')
# Find first line with 64 ints
flag_hash = None
for line in text.split("\n"):
    cleaned = re.sub(r'[^0-9 -]', ' ', line)
    nums = []
    for t in cleaned.split():
        try: nums.append(int(t))
        except: pass
    if len(nums) == 64:
        flag_hash = nums; break
log(f"flag_hash[:5] = {flag_hash[:5]}")

def multi_hash_batch(vecs):
    """Query multi_hash with n vectors. Each printed "hash" has size n (NOT 64) due
    to the binary's res_mat layout — the col_vec length is MatRows(res_mat) = n.
    For n ≤ 64 this is fine; the first 64 entries are the real hash, the rest is
    zero-padding/wrap into msgs[i+1]. So take the FIRST 64 ints of each line."""
    n = len(vecs)
    cmd = f"2\n{n}\n"
    for v in vecs:
        cmd += "2\n" + " ".join(str(x) for x in v) + "\n"
    write(cmd)
    buf = expect_until(b"Your choice: ")
    text = buf.decode(errors='replace')
    cleaned = re.sub(r'[^0-9 \n-]', ' ', text)
    hashes = []
    # Each true hash line has exactly n ints (or more on line 0 due to prompt prefix).
    for line in cleaned.split("\n"):
        toks = line.split()
        run = []
        for t in toks:
            try: run.append(int(t))
            except: run = []
        if len(run) == n:
            hashes.append(run[:64])
        elif len(run) > n:
            # First line includes prompt digits before the real n-int hash.
            hashes.append(run[-n:][:64])
    return hashes[:n]

# Query A via multi_hash batches of EXACTLY 64. The binary's multi_hash returns
# a vec of length n per "hash", but the underlying buffer only has the real
# (A · msg_i)[0..63] when n == 64 (n < 64 truncates; n > 64 wraps into msgs[i+1]).
# So use n=64 with padding for the last partial batch.
log("Querying A...")
A_cols = []
batch_size = 64
for start in range(0, M, batch_size):
    end = min(start + batch_size, M)
    real = end - start
    vecs = []
    for c in range(start, end):
        v = [0]*M; v[c] = 1
        vecs.append(v)
    # Pad up to exactly 64 so each printed hash has full 64 ints.
    while len(vecs) < batch_size:
        vecs.append([0]*M)
    hashes = multi_hash_batch(vecs)
    log(f"  batch {start}..{end-1}: got {len(hashes)} hashes (real={real})")
    if len(hashes) != batch_size:
        log(f"  MISMATCH! expected {batch_size} got {len(hashes)}")
        sys.exit(1)
    A_cols.extend(hashes[:real])

A = np.array(A_cols).T  # N × M
assert A.shape == (N, M)
log(f"A recovered shape={A.shape}")

# Start application-level heartbeat to keep the kitctf proxy from closing the idle SSL connection.
import threading
io_lock = threading.Lock()
heartbeat_stop = threading.Event()
def heartbeat():
    """Send a single multi_hash(n=1) every 20s while BKZ runs."""
    v = [0]*M
    while not heartbeat_stop.is_set():
        if heartbeat_stop.wait(20): return
        try:
            with io_lock:
                if heartbeat_stop.is_set(): return
                cmd = f"2\n1\n2\n" + " ".join(str(x) for x in v) + "\n"
                io.write(cmd.encode()); io.flush()
                # read response
                buf = b""
                while b"Your choice: " not in buf:
                    ch = io.read(1)
                    if not ch: log("heartbeat: EOF"); return
                    buf += ch
                log(f"heartbeat ok at {time.time()-T0:.1f}s")
        except Exception as e:
            log(f"heartbeat error: {e}")
            return
hb_thread = threading.Thread(target=heartbeat, daemon=True)
hb_thread.start()

# Build lattice
A_sp = Matrix(A.tolist())
A1 = A_sp[:, :N]
A2 = A_sp[:, N:]
A1_inv = A1.inv_mod(Q)
A1_inv_np = np.array(A1_inv.tolist(), dtype=object) % Q
A2_np = np.array(A2.tolist(), dtype=object) % Q

OFFSET = 5
ones = np.ones(M, dtype=int)
offset_t = (A @ (OFFSET * ones)) % Q
t_prime = [(flag_hash[i] - int(offset_t[i])) % Q for i in range(N)]

s0 = np.zeros(M, dtype=object)
s0[:N] = (A1_inv_np @ np.array(t_prime, dtype=object)) % Q

T = (-A1_inv_np @ A2_np) % Q
basis = np.zeros((M, M), dtype=int)
for j in range(M - N):
    for i in range(N):
        basis[j, i] = int(T[i, j])
    basis[j, N + j] = 1
for j in range(N):
    basis[M - N + j, j] = Q

K = 1
n_lat = M + 1
B = np.zeros((n_lat, n_lat), dtype=int)
B[:M, :M] = basis
s0_int = np.array([int(x) for x in s0])
s0_centered = np.where(s0_int > Q // 2, s0_int - Q, s0_int)
B[M, :M] = s0_centered
B[M, M] = K

mat = IntegerMatrix.from_matrix(B.tolist())
log("LLL…")
LLL.reduction(mat)
log("LLL done")

def try_extract():
    for i in range(n_lat):
        row = [mat[i, j] for j in range(n_lat)]
        if abs(row[M]) != K: continue
        sign = 1 if row[M] == K else -1
        head = [sign * x for x in row[:M]]
        # head should be s_centered ≈ s - OFFSET
        for cand_fn in (lambda h: h + OFFSET, lambda h: -h + OFFSET):
            s_cand = [cand_fn(h) for h in head]
            if all(0 <= v <= 9 for v in s_cand):
                check = (A @ np.array(s_cand)) % Q
                if all(int(check[k]) == flag_hash[k] for k in range(N)):
                    return s_cand
    return None

s = try_extract()
budget = 195 - (time.time() - T0)
log(f"Budget remaining: {budget:.1f}s")

if s is None:
    # Progressive BKZ-2.0 with strategies (preprocessing + pruning). NO GH_BND — it skips our target.
    for bs, ml in [(30,2),(40,2),(50,2),(55,2),(58,2),(60,2),(62,1),(64,1)]:
        if time.time() - T0 > 180: break
        log(f"BKZ-{bs} ml={ml}…")
        t1 = time.time()
        try:
            BKZ.reduction(mat, BKZ.Param(block_size=bs, strategies=STRAT_BYTES,
                                          flags=BKZ.AUTO_ABORT, max_loops=ml))
        except Exception as e:
            log(f"  BKZ-{bs} exception: {e}")
            break
        log(f"  BKZ-{bs} done in {time.time()-t1:.1f}s")
        s = try_extract()
        if s: log(f"BKZ-{bs} found!"); break

if s is None:
    log("LATTICE FAILED — leaking secret instead")
    # Send a guess of all zeros; server prints secret then exits
    write("0\n" + "0 "*M + "\n")
    buf = b""
    t1 = time.time()
    while time.time() - t1 < 5:
        try: ch = io.read(1)
        except: break
        if not ch: break
        buf += ch
    text = buf.decode(errors='replace')
    print(text[-2000:], file=sys.stderr)
    sys.exit(0)

log(f"Recovered s; verifying locally…")
verify = (A @ np.array(s)) % Q
ok = all(int(verify[k]) == flag_hash[k] for k in range(N))
log(f"verify: {ok}; s[:10]={s[:10]}")
log(f"Stopping heartbeat & submitting…")
heartbeat_stop.set()
with io_lock:
    write("0\n" + " ".join(str(x) for x in s) + "\n")
import socket as _s
sock.settimeout(20)
buf = b""
t1 = time.time()
try:
    while time.time() - t1 < 20:
        try: ch = sock.recv(4096)
        except _s.timeout: break
        except Exception as e: log(f"recv error: {e}"); break
        if not ch: log("recv EOF"); break
        buf += ch
        if b"GPN" in buf: break
except Exception as e:
    log(f"outer recv error: {e}")
text = buf.decode(errors='replace')
log(f"received {len(buf)} bytes")
print("---RESPONSE---", file=sys.stderr)
print(text, file=sys.stderr)
print("---END---", file=sys.stderr)
print("=== FLAG ===")
for line in text.split("\n"):
    if "GPN" in line.upper():
        print(line)
