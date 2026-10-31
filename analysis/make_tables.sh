#!/bin/sh
# Regenerate every table of the article from the data package.
set -e
cd "$(dirname "$0")"
python3 load.py ../data/ablation pkg.pkl
python3 emit_tex.py > tables_regenerated.tex
python3 extra.py > text_numbers_regenerated.txt
echo "wrote tables_regenerated.tex and text_numbers_regenerated.txt"
