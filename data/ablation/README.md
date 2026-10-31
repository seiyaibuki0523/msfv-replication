# `data/ablation/` — distributed through Zenodo, not through git

The 132 run directories (964 configurations, 3,024 files, 2.8 GB) described in section 1 of the package
README live in the archived package on Zenodo, not in this repository. From the repository root run

    scripts/fetch_zenodo_data.sh

It downloads `msfv-replication-package-v1.0.tar.gz` from <https://doi.org/10.5281/zenodo.22704663>
(24 parts), verifies every part and the reassembled archive against the published SHA-256 sums
(`e948413aba7d7ad193a3170cd0d5792079c7cf578d3a08d6df67e9a1525fc3cc`), extracts `data/ablation/` here and
checks the 3,024 extracted files against `CHECKSUMS.sha256`. Everything under this directory except this
file is ignored by git (see `.gitignore` at the repository root).
