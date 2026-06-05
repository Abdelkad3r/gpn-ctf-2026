"""Remote solver: leak A via multi_hash, run BKZ in <190s, submit."""
import sys, socket, ssl, time, re
import numpy as np
from fpylll import IntegerMatrix, BKZ, LLL
from sympy import Matrix

HOST = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
N, M, Q = 64, 164, 12289
T0 = time.time()
def log(msg): print(f"[{time.time()-T0:6.1f}s] {msg}", file=sys.stderr, flush=True)

def connect(host, port):
    sock = ssl.create_default_context().wrap_socket(
        socket.create_connection((host, port)), server_hostname=host)
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
    """Query multi_hash with n vectors (each [2]custom), return list of 64-int hashes."""
    n = len(vecs)
    cmd = f"2\n{n}\n"
    for v in vecs:
        cmd += "2\n" + " ".join(str(x) for x in v) + "\n"
    write(cmd)
    buf = expect_until(b"Your choice: ")
    text = buf.decode(errors='replace')
    # Parse all integer-only lines (after stripping non-digit/space prefix)
    cleaned = re.sub(r'[^0-9 \n-]', ' ', text)
    hashes = []
    for line in cleaned.split("\n"):
        toks = line.split()
        # Collect ints from right side (handle prefix junk)
        run = []
        for t in toks:
            try: run.append(int(t))
            except: run = []
        if len(run) == 64:
            hashes.append(run)
        elif len(run) > 64:
            hashes.append(run[-64:])
    return hashes[:n]

# Query A via 2 multi_hash batches
log("Querying A...")
A_cols = []
batch_size = 100
for start in range(0, M, batch_size):
    end = min(start + batch_size, M)
    vecs = []
    for c in range(start, end):
        v = [0]*M; v[c] = 1
        vecs.append(v)
    hashes = multi_hash_batch(vecs)
    log(f"  batch {start}..{end-1}: got {len(hashes)} hashes")
    if len(hashes) != end - start:
        log(f"  MISMATCH! expected {end-start} got {len(hashes)}")
        sys.exit(1)
    A_cols.extend(hashes)

A = np.array(A_cols).T  # N × M
assert A.shape == (N, M)
log(f"A recovered shape={A.shape}")

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
    for bs, ml in [(25,2),(30,2),(35,2),(38,2),(40,2),(42,2),(44,1)]:
        if time.time() - T0 > 185: break
        log(f"BKZ-{bs} ml={ml}…")
        t1 = time.time()
        try:
            BKZ.reduction(mat, BKZ.Param(block_size=bs, flags=BKZ.AUTO_ABORT, max_loops=ml))
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

log(f"Recovered s, submitting…")
write("0\n" + " ".join(str(x) for x in s) + "\n")
buf = b""
t1 = time.time()
while time.time() - t1 < 10:
    try: ch = io.read(1)
    except: break
    if not ch: break
    buf += ch
text = buf.decode(errors='replace')
print(text, file=sys.stderr)
print("=== FLAG ===")
for line in text.split("\n"):
    if "GPN" in line.upper():
        print(line)
