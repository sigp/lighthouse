# PQ timing reports

Run a syncing devnet-0 beacon node without a validator client. Pass the network, execution layer and leanVM sidecar settings used by your deployment, and add:

```sh
lighthouse beacon_node --testnet-dir /path/to/devnet-0 \
  --execution-endpoint http://127.0.0.1:8551 --execution-jwt /path/to/jwt.hex \
  --pq-prover-socket /path/to/leanvm.sock \
  --pq-measurement --pq-timing-output /path/to/timing-runs
```

The existing `lighthouse-pq-bn` launcher supplies the socket when it starts its own sidecar. Observer mode enables every configured attestation subnet and plans one experiment every three slots. The experiment receives real network inputs and uses the real proving lane. Synthetic outputs stay private. A regular validator-serving beacon node can use `--pq-timing-output` alone to export its real workload.

The output root contains one directory per process run. It holds `run.json` and finalized `events-*.jsonl.zst` chunks. Temporary chunks end in `.partial`. The manifest records which chunks are available, queue drops and retention gaps. Terminate the beacon node normally to finish the last chunk. Aggregate operation durations use a monotonic clock, and receive/completion placement uses the recorded wall/slot clock. Receipts are stamped after libp2p's Snappy transform and deduplication, before SSZ decode. Rollovers retain their full offset from the reference slot.

```sh
python3 -m pip install 'matplotlib>=3.10,<4' 'zstandard>=0.20,<1'
python3 scripts/pq-measurement/plot.py /path/to/timing-runs/run-id --output reports
```

The renderer emits PNG and SVG per scenario and known geometry, plus a receipt-only overview. Use `--scenario combined` to select the combined schedule and `--mean` to show means. R1 is the initial merge phase. An initial single-proof reuse produces no backend timing point, and the first improvement is still R2. Median checked readiness is shown separately from backend completion. Arrivals are message-weighted and deduplicated by network message ID within one run. The raw export retains arrivals for all observed slots, while scenario plots use arrivals for their reference slots. No proof or signature payloads are exported.

Run the report logic checks with `python3 scripts/pq-measurement/test_plot.py`.
