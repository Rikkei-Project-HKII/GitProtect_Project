# Reproducible 200-case dataset

Run `python generate_benchmark_dataset.py` to write `tests/benchmark_dataset_200.json` locally. The file is intentionally ignored because synthetic provider-shaped tokens can trigger secret scanning. The fixed seed 20261123 reproduces 100 positive and 100 negative cases with rule/severity labels. `python scripts/run_benchmark.py` builds the same data in memory. Never substitute issued credentials.
