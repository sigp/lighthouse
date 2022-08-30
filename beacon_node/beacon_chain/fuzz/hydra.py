#!/usr/bin/env python3
import argparse
import subprocess
import sys

FUZZ_TARGET = "fuzzer"
REPRO_TARGET = "repro"

def build_fuzz_target(args):
    spec = args.spec
    subprocess.run(
        [
            "cargo",
            "+nightly",
            "afl",
            "build",
            "--release",
            "--bin",
            FUZZ_TARGET,
            "--features",
            f"afl,{spec}",
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

def build_repro_target(args):
    spec = args.spec
    subprocess.run(
        [
            "cargo",
            "+nightly",
            "build",
            "--release",
            "--bin",
            REPRO_TARGET,
            "--features",
            f"{spec}",
            "--features",
            "logging/test_logger",
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

def fuzz_command(i):
    return [
       "cargo",
       "+nightly",
       "afl",
       "fuzz",
       "-i"
       "data/in",
       "-o",
       "data/out",
       "-S",
       f"worker{i}",
       "-t",
       "60000",
       f"target/release/{FUZZ_TARGET}"
    ]

def run(args):
    if args.num_workers == 1:
        run_single(args)
    else:
        run_multi(args)

def run_single(args):
    # Build with AFL.
    build_fuzz_target(args)

    # Fuzz the compiled binary.
    subprocess.run(
        fuzz_command(0),
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

def run_multi(args):
    # Build with AFL.
    build_fuzz_target(args)

    # Start a screen session.
    print("starting `screen` session")
    subprocess.check_call(
        [
            "screen",
            "-d",
            "-m",
            "-S",
            "hydra",
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    subprocess.check_call(
        ["screen", "-S", "hydra", "-X", "zombie", "qr"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    for i in range(0, args.num_workers):
        print(f"starting worker{i}")
        subprocess.check_call(
            [
                "screen",
                "-S",
                "hydra",
                "-X",
                "screen",
                *fuzz_command(i)
            ],
            stdout=sys.stdout,
            stderr=sys.stderr
        )


def repro(args):
    build_repro_target(args)

    with open(args.input, "rb") as f:
        input_bytes = f.read()

    subprocess.run(
        [
            f"target/release/{REPRO_TARGET}"
        ],
        input=input_bytes,
        stdout=sys.stdout,
        stderr=sys.stderr
    )

def parse_args():
    parser = argparse.ArgumentParser(prog="hydra")
    subparsers = parser.add_subparsers()

    run_parser = subparsers.add_parser("run", help="Start a fuzzing session with AFL")
    run_parser.add_argument("--spec", default="mainnet")
    run_parser.add_argument("--num-workers", metavar="N", type=int, default=1)
    run_parser.add_argument("--reorg-limit", metavar="N", type=int, default=5)
    run_parser.set_defaults(func=run)

    repro_parser = subparsers.add_parser("repro", help="Reproduce a crash with debugging output")
    repro_parser.add_argument("--spec", default="mainnet")
    repro_parser.add_argument("input", metavar="FILE")
    repro_parser.set_defaults(func=repro)

    return parser.parse_args()

def main():
    args = parse_args()

    # Invoke appropriate subcommand
    args.func(args)

if __name__ == "__main__":
    main()
