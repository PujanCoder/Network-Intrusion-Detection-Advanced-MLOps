"""Batch training entry point.

Kept so ``python train.py`` keeps working. The pipeline itself lives in
``src/pipelines/pipeline.py`` and is orchestrated by DVC (``dvc repro``), which
is the supported way to train: it records the exact data and parameter hashes.
"""

from src.pipelines.pipeline import run_pipeline

if __name__ == "__main__":
    run_pipeline()
