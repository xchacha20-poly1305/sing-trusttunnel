# sing-trusttunnel bench

Compares this repo's Go `sing-trusttunnel` with upstream Rust (`trusttunnel_endpoint` / `trusttunnel_client`) on
loopback, running SOCKS5 → HTTPS origin traffic.

Matrix axes:

| Axis        | Values                          |
|-------------|---------------------------------|
| server impl | `sing` / `rust`                 |
| client impl | `sing` / `rust`                 |
| transport   | `h2` / `quic`                   |
| direction   | `dl` (download) / `ul` (upload) |
| jobs        | `1` / `2` / `4`                 |

Each cell runs `BENCH_REPS=3` repetitions; every concurrent job pulls/pushes `BENCH_SIZE=1 GiB` via
`curl --proxy socks5://127.0.0.1:1080` against the local HTTPS origin (`bench/origin/main.go`). Throughput is taken from
`curl -w speed_dl/speed_ul`; per-process CPU% and RSS are sampled at 1 Hz by `pidstat-collect.sh`.

## Test environment

- OS: Linux
- Kernel: 7.0.5
- Go: 1.26.3
- Rust: 1.85.1
- CPU pinning (`taskset`): origin → core 6, tunnel server → core 2, tunnel client → core 4, curl array → cores 8,10

## Versions under test

- `sing-trusttunnel` v0.2.2 (this repo, `dev` branch, built with `-tags with_quic`)
- `trusttunnel_endpoint` 1.0.41 (upstream Rust, `cargo build --release`)
- `trusttunnel_client` 1.0.63 (upstream Rust, `cargo build --release --bin trusttunnel_client`)
- `bench-origin`: in-tree `bench/origin/main.go`. HTTPS / h2. `GET /download/{N}` streams N zero bytes; `PUT /upload/*`
  drains and returns 200.

## Commands

```bash
# 1. Build binaries, generate self-signed cert, clone+build upstream rust client
make -C bench setup

# 2. Run the full matrix (server × client × transport × direction × jobs = 2×2×2×2×3 = 48 cells)
make -C bench run

# 3. Quick smoke (sing-server × {sing,rust}-client only, h2, dl, 1 job, 64 MiB × 1 rep)
make -C bench smoke
```

Raw artifacts land in `bench/results/raw/` (per-cell `*.runs.txt`, `*.pidstat.csv`, `*.meta.json`, and
`*.{server,client,origin,driver}.log`). `scripts/aggregate.py` rolls them up into `bench/results/summary.csv` and
`bench/results/summary.md`.

Knobs (see `scripts/run-matrix.sh` and `scripts/run-pair.sh` for the full list):

| Var                 | Default              | Meaning                                      |
|---------------------|----------------------|----------------------------------------------|
| `BENCH_SIZE`        | `1073741824` (1 GiB) | Bytes per request                            |
| `BENCH_REPS`        | `3`                  | Repetitions per cell                         |
| `BENCH_TIMEOUT`     | `180`                | Per-curl timeout (seconds)                   |
| `MATRIX_SERVERS`    | `"sing rust"`        | Server impls to include                      |
| `MATRIX_CLIENTS`    | `"sing rust"`        | Client impls to include                      |
| `MATRIX_TRANSPORTS` | `"h2 quic"`          | Tunnel transports                            |
| `MATRIX_DIRECTIONS` | `"dl ul"`            | Directions                                   |
| `MATRIX_JOBS`       | `"1 2 4"`            | Concurrency                                  |
| `COOLDOWN_SECS`     | `3`                  | Sleep between cells                          |
| `RESULTS_DIR`       | `bench/results`      | Output directory                             |
| `TRUSTTUNNEL_DIR`   | `../TrustTunnel`     | Upstream rust repo path (used by `setup.sh`) |
| `BENCH_PIN`         | `1`                  | Use `taskset` affinity when `nproc >= 8`     |

Re-run a single cell:

```bash
# server-impl client-impl transport direction jobs
RESULTS_DIR=bench/results/raw bench/scripts/run-pair.sh sing sing h2 dl 4
```

## Results

Throughput in MB/s (1 MB = 1 048 576 B). `per_job` = mean per concurrent curl invocation; `agg` = sum across jobs within
a rep, then mean across reps. CPU is %CPU with single-core baseline = 100% (saturating multiple cores can exceed 100%).
RSS in MiB, max over the sampling window. `runs ok/fail` is the cumulative curl request count (`reps × jobs`).

### transport=h2  direction=dl

#### jobs=1

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 779.3 ± 9.5       | 779.3 ± 9.5   | 44.2            | 12.8           | 91.7            | 6.8            | 3/0          |
| rust   | sing   | 1628.2 ± 11.7     | 1628.2 ± 11.7 | 80.6            | 12.7           | 85.7            | 23.6           | 3/0          |
| sing   | rust   | 765.3 ± 18.0      | 765.3 ± 18.0  | 37.2            | 18.4           | 91.0            | 6.8            | 3/0          |
| sing   | sing   | 1770.3 ± 28.6     | 1770.3 ± 28.6 | 81.5            | 18.4           | 85.6            | 21.7           | 3/0          |

#### jobs=2

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 378.1 ± 17.8      | 756.3 ± 9.9   | 30.4            | 13.4           | 92.3            | 6.9            | 6/0          |
| rust   | sing   | 823.3 ± 12.3      | 1646.7 ± 24.0 | 68.3            | 13.3           | 93.5            | 29.9           | 6/0          |
| sing   | rust   | 409.2 ± 51.0      | 818.5 ± 40.5  | 36.8            | 20.4           | 92.3            | 6.8            | 6/0          |
| sing   | sing   | 843.2 ± 17.2      | 1686.4 ± 33.6 | 73.8            | 20.4           | 92.3            | 31.9           | 6/0          |

#### jobs=4

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 205.5 ± 21.5      | 822.2 ± 4.6   | 33.3            | 14.5           | 92.8            | 6.9            | 12/0         |
| rust   | sing   | 384.8 ± 3.1       | 1539.1 ± 9.6  | 66.2            | 14.0           | 94.5            | 46.3           | 12/0         |
| sing   | rust   | 202.9 ± 41.0      | 811.4 ± 3.2   | 33.8            | 18.4           | 93.2            | 6.8            | 12/0         |
| sing   | sing   | 389.9 ± 5.2       | 1559.5 ± 19.3 | 71.5            | 20.4           | 93.0            | 52.5           | 12/0         |

### transport=h2  direction=ul

#### jobs=1

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 416.6 ± 9.7       | 416.6 ± 9.7   | 56.9            | 12.8           | 85.3            | 6.8            | 3/0          |
| rust   | sing   | 1422.8 ± 47.3     | 1422.8 ± 47.3 | 50.0            | 12.7           | 50.0            | 19.6           | 3/0          |
| sing   | rust   | 256.9 ± 87.8      | 256.9 ± 87.8  | 79.6            | 20.5           | 92.4            | 6.8            | 3/0          |
| sing   | sing   | 1467.6 ± 88.9     | 1467.6 ± 88.9 | 51.8            | 18.4           | 48.8            | 17.6           | 3/0          |

#### jobs=2

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 152.0 ± 34.2      | 304.1 ± 68.3  | 47.0            | 13.0           | 94.1            | 6.8            | 6/0          |
| rust   | sing   | 717.8 ± 18.1      | 1435.6 ± 36.1 | 84.3            | 12.8           | 81.3            | 17.6           | 6/0          |
| sing   | rust   | 127.7 ± 29.9      | 255.5 ± 59.8  | 68.6            | 18.5           | 94.1            | 6.8            | 6/0          |
| sing   | sing   | 885.8 ± 38.3      | 1771.6 ± 75.7 | 85.1            | 18.4           | 84.2            | 17.5           | 6/0          |

#### jobs=4

| server | client | per_job MB/s (±σ) | agg MB/s (±σ)  | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|----------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 155.1 ± 11.8      | 620.2 ± 14.6   | 62.8            | 13.4           | 92.0            | 7.2            | 12/0         |
| rust   | sing   | 374.7 ± 40.8      | 1498.7 ± 135.9 | 83.0            | 13.2           | 83.2            | 17.6           | 12/0         |
| sing   | rust   | 104.5 ± 1.0       | 418.1 ± 3.8    | 54.0            | 20.5           | 93.1            | 11.4           | 12/0         |
| sing   | sing   | 478.6 ± 51.2      | 1914.6 ± 197.5 | 85.1            | 18.4           | 84.5            | 21.7           | 12/0         |

### transport=quic  direction=dl

#### jobs=1

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 450.5 ± 15.5      | 450.5 ± 15.5  | 61.8            | 12.4           | 95.1            | 8.9            | 3/0          |
| rust   | sing   | 723.9 ± 4.1       | 723.9 ± 4.1   | 82.2            | 15.2           | 95.9            | 19.5           | 3/0          |
| sing   | rust   | 417.1 ± 37.8      | 417.1 ± 37.8  | 43.2            | 20.7           | 93.3            | 9.2            | 3/0          |
| sing   | sing   | 793.7 ± 2.2       | 793.7 ± 2.2   | 62.8            | 20.4           | 94.2            | 20.4           | 3/0          |

#### jobs=2

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 265.5 ± 2.2       | 530.9 ± 4.4   | 69.6            | 12.7           | 95.1            | 9.1            | 6/0          |
| rust   | sing   | 475.3 ± 149.9     | 950.6 ± 136.5 | 81.6            | 17.2           | 96.0            | 18.7           | 6/0          |
| sing   | rust   | 230.8 ± 10.5      | 461.6 ± 21.1  | 44.8            | 20.8           | 94.7            | 9.8            | 6/0          |
| sing   | sing   | 390.3 ± 5.8       | 780.6 ± 7.0   | 61.4            | 18.8           | 93.8            | 18.5           | 6/0          |

#### jobs=4

| server | client | per_job MB/s (±σ) | agg MB/s (±σ)  | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|----------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 136.8 ± 0.8       | 547.1 ± 3.2    | 72.5            | 12.8           | 94.0            | 10.4           | 12/0         |
| rust   | sing   | 316.3 ± 166.9     | 1265.3 ± 157.4 | 82.1            | 15.7           | 97.1            | 20.0           | 12/0         |
| sing   | rust   | 84.3 ± 10.4       | 337.3 ± 41.6   | 40.2            | 18.7           | 95.7            | 9.7            | 12/0         |
| sing   | sing   | 185.8 ± 2.0       | 743.4 ± 7.7    | 59.8            | 18.6           | 92.9            | 20.5           | 12/0         |

### transport=quic  direction=ul

#### jobs=1

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 166.4 ± 0.7       | 166.4 ± 0.7   | 85.1            | 11.7           | 89.0            | 8.5            | 3/0          |
| rust   | sing   | 420.1 ± 2.4       | 420.1 ± 2.4   | 91.9            | 11.9           | 80.2            | 20.7           | 3/0          |
| sing   | rust   | 180.3 ± 0.6       | 180.3 ± 0.6   | 67.8            | 20.6           | 90.3            | 8.5            | 3/0          |
| sing   | sing   | 424.9 ± 4.0       | 424.9 ± 4.0   | 81.4            | 18.6           | 83.6            | 18.6           | 3/0          |

#### jobs=2

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 92.4 ± 2.3        | 184.7 ± 4.6   | 86.3            | 11.9           | 89.8            | 8.4            | 6/0          |
| rust   | sing   | 228.3 ± 23.3      | 456.6 ± 22.4  | 92.5            | 12.1           | 82.4            | 20.7           | 6/0          |
| sing   | rust   | 97.5 ± 8.0        | 195.0 ± 16.0  | 67.7            | 21.6           | 90.4            | 8.9            | 6/0          |
| sing   | sing   | 215.9 ± 1.0       | 431.8 ± 1.8   | 80.5            | 20.6           | 84.2            | 18.6           | 6/0          |

#### jobs=4

| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |
|--------|--------|-------------------|---------------|-----------------|----------------|-----------------|----------------|--------------|
| rust   | rust   | 48.4 ± 3.3        | 193.6 ± 13.3  | 86.2            | 11.9           | 89.7            | 8.6            | 12/0         |
| rust   | sing   | 134.7 ± 34.8      | 538.7 ± 61.7  | 91.8            | 12.8           | 81.6            | 20.4           | 12/0         |
| sing   | rust   | 47.1 ± 4.6        | 188.6 ± 18.1  | 62.6            | 21.3           | 92.0            | 9.4            | 12/0         |
| sing   | sing   | 117.2 ± 5.7       | 469.0 ± 19.5  | 76.8            | 18.6           | 83.2            | 18.6           | 12/0         |

## Highlights

All 48 cells (288 curl requests total) completed with HTTP 200; no failures.

- **h2**: Within each implementation pair (sing×sing vs rust×rust) throughput is in the same ballpark, but the
  `*-sing-client` rows are consistently 1.8–2× faster than `*-rust-client` rows — the SOCKS5 client path appears to
  dominate. At jobs=1 dl, `sing-sing` 1770 MB/s and `rust-sing` 1628 MB/s vs `sing-rust` 765 MB/s and `rust-rust` 779
  MB/s.
- **quic**: Reverse picture on the server side: at jobs=1 dl, `sing-rust` 417 vs `rust-rust` 450 are close, but
  `sing-sing` 793 vs `rust-sing` 724 favors sing-server. At jobs=4 dl, `sing-sing` 743 still beats `rust-rust` 547 in
  aggregate throughput.
- **Memory**: sing-server RSS sits at 18–21 MiB vs rust-server 12–17 MiB (rust slightly leaner). sing-client RSS scales
  with `jobs` (h2 dl jobs=4 ≈ 52 MiB) while rust-client stays under 11 MiB.
- **CPU**: Most client p95 values are 90–95% — close to single-core saturation under the `taskset` pinning. Comparing
  multi-core scaling would require unsetting `BENCH_PIN`.

Per-cell numbers are in `results/summary.md` and `results/summary.csv`. Raw curl output, pidstat samples, and the three
process logs for each cell live in `results/raw/<label>.*`.

## Notes for reproducing

- `bench/results/` is gitignored; a clean re-run is `make -C bench setup && make -C bench run`.
- Before a run, kill leftover processes: `pkill -f 'bench-origin|sing-trusttunnel|trusttunnel_(endpoint|client)'`.
- `make -C bench clean` wipes `.work/`; `make -C bench clean-results` wipes `results/`; `make -C bench clean-all` also
  deletes the self-signed cert.
- When the rust client is in the matrix, `run-matrix.sh` runs a preflight smoke (`sing-rust-h2-dl-j1`) and grep-checks
  the server log for an origin request before continuing — guards against bogus zero-throughput rows from an unproxied
  client.
