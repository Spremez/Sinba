# BatchPIR (BGV/BatchEncoder) – Single & Batch query test harness

This folder contains a self-contained prototype implementation of:
- **Single-query PIR** (2D BSGS as in your existing code)
- **Batch-query PIR** with **bucketed cuckoo placement**, and the **slot layout + pre-rotation logic** you specified.

Key goals:
- Deterministic (reproducible) cuckoo placement for batch mode.
- Deterministic pseudo-random DB generation when the full raw DB would be too large to materialize.
- A runnable `pir_test` binary that can be parameterized from the command line for paper experiments.

## Build

### Option A: Using an installed Microsoft SEAL

Assuming SEAL exports `SEAL::seal` via CMake config:

```bash
mkdir -p build && cd build
cmake -DSEAL_DIR=/path/to/seal/cmake ..
cmake --build . -j
```

### Option B: Build SEAL as a subdirectory

Put SEAL source at `vendor/SEAL`:

```bash
mkdir -p build && cd build
cmake -DPIR_USE_SEAL_SUBDIR=ON ..
cmake --build . -j
```

## Run

`pir_test` runs both single and batch by default.

```bash
./pir_test
```

Common experiment flags:

```bash
# Single only
./pir_test --single-only --entries 1048576 --payload 64 --iters-single 20 --warmup-single 5

# Batch only (often uses smaller DB size by default)
./pir_test --batch-only --batch-entries 65536 --batch-size 32 --payload 64 --iters-batch 10 --warmup-batch 3

# Adjust cuckoo settings (default cuckoo_factor=1.5, hash-funcs=3)
./pir_test --batch-only --cuckoo-factor 1.5 --hash-funcs 3
```

Notes:
- If `num_entries * slots_per_entry` would exceed ~512 MiB of raw DB storage, the encoder automatically switches to a deterministic PRG-backed DB (so the test stays runnable).
- However, the plaintext matrix itself can still become huge if you choose incompatible `(entries, payload)` settings. Prefer starting with `payload=64` and scaling carefully.
