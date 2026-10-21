import os, time
def run(path, prezero, n=300, chunk=64*1024):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    size = n * chunk
    if prezero:
        os.write(fd, b"\0" * size); os.fsync(fd)
    else:
        os.ftruncate(fd, 1 << 30)  # sparse, like a log segment
    buf = os.urandom(chunk)
    t = []
    for i in range(n):
        os.pwrite(fd, buf, i * chunk)
        a = time.perf_counter(); os.fdatasync(fd); t.append(time.perf_counter() - a)
    os.close(fd); os.unlink(path)
    t.sort()
    return t[len(t)//2]*1e3, t[int(len(t)*0.99)]*1e3
for label, pz in [("sparse (fill holes)", False), ("pre-zeroed (overwrite)", True)]:
    p50, p99 = run("/root/bench/fsync-test.bin", pz)
    print(f"{label:24s} fdatasync of 64 KiB: p50 {p50:.2f} ms, p99 {p99:.2f} ms")
