# Memory Profiling in Lighthouse

Lighthouse ships with jemalloc enabled by default on Linux, with heap profiling (`prof:true,prof_active:false`) already configured. This guide explains how to capture and inspect heap profiles using `jeprof` to help diagnose memory issues. Use this profiling setup to catch leaks, regressions, or bloated allocation paths.

## 1. Build Lighthouse with Debug Symbols

To make the profiling data readable, build Lighthouse with debug symbols:

```bash
RUSTFLAGS="-C debuginfo=2" make
```

This ensures the installed `lighthouse` binary includes symbol information. `debug = true` in Cargo profiles is more expansive (enabling `opt-level = 0`, e.g.), but `debuginfo=2` is sufficient and better suited for profiling with optimized binaries.

## 2. Run the Beacon Node

Run the node as usual:

```bash
lighthouse bn ...
```

Let it run for a while to accumulate allocations if desired. Note that jemalloc only records allocations after profiling is activated - consider this when deciding when to start profiling.

> **Be consistent:** When analyzing a profile dump, `jeprof` must be given the exact path to the binary used to launch the process. In this setup, it's simply `$(which lighthouse)`.

## 3. Start Profiling and Dump Memory

Enable jemalloc profiling:

```bash
curl -X POST http://localhost:5052/lighthouse/malloc/prof_active -H "Content-Type: application/json" -d "true"
```

Trigger a memory profile dump:

```bash
curl -X POST http://localhost:5052/lighthouse/malloc/prof_dump -H "Content-Type: application/json" -d '"/home/ubuntu/prof.dump"'
```

## 4. Analyze with `jeprof`

Generate a visualization:

```bash
jeprof --svg $(which lighthouse) /home/ubuntu/prof.dump > profile.svg
```

Open `profile.svg` in a browser to inspect memory usage.

> **Important:** Symbol resolution will fail if the path to `lighthouse` doesn't exactly match how it was invoked. Stick to `$(which lighthouse)` if that's how the binary was executed.
