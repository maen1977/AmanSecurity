#!/usr/bin/env python3
from pathlib import Path
import subprocess,sys,csv
ROOT=Path(__file__).resolve().parents[1]
bench=(ROOT/'tools/benchmark_detection.py').read_text()
for marker in ['--require-reviewed','--min-samples','--min-malicious','--min-benign','sample_sha256','review_status','source_group']:
    if marker not in bench: raise SystemExit(f'PRODUCTION_VALIDATION_GATE_FAILED benchmark_missing={marker}')
reviewed=ROOT/'benchmarks/reviewed_detection_results.csv'
if not reviewed.exists(): raise SystemExit('PRODUCTION_VALIDATION_GATE_FAILED reviewed_template_missing')
with reviewed.open(newline='',encoding='utf-8') as f:
    fields=next(csv.reader(f),[])
required={'case_id','sample_sha256','review_status','source_group','expected_malicious','score'}
if not required.issubset(fields): raise SystemExit('PRODUCTION_VALIDATION_GATE_FAILED reviewed_columns')
for suffix in ('.apk','.dex','.exe','.elf','.so'):
    bad=[p for p in (ROOT/'benchmarks').rglob(f'*{suffix}') if p.is_file()]
    if bad: raise SystemExit(f'PRODUCTION_VALIDATION_GATE_FAILED sample_binaries={bad}')
subprocess.run([sys.executable,str(ROOT/'tools/benchmark_detection.py'),str(ROOT/'benchmarks/regression_detection.csv'),
                '--min-samples','30','--min-malicious','15','--min-benign','15','--min-detection-rate','1.0','--max-false-positive-rate','0.0'],check=True)
subprocess.run([sys.executable,str(ROOT/'tools/benchmark_detection.py'),str(ROOT/'benchmarks/false_positive_stress.csv'),
                '--min-samples','16','--min-benign','16','--max-false-positive-rate','0.0'],check=True)
print('PRODUCTION_VALIDATION_INFRA_GATE_OK internal_regression=30 false_positive_stress=16 reviewed_corpus_template=1 malware_binaries=0 real_world_claim=0')
