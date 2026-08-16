#!/usr/bin/env python3
"""Evaluate exported Aman Security verdicts without handling malware binaries.

Required CSV columns: expected_malicious,score
Optional: scan_ms,peak_memory_mb,expected_family,predicted_family,case_id,
          sample_sha256,review_status,source_group

Threshold options turn the evaluator into a CI/validation quality gate. This tool
measures only the supplied exported verdict corpus; it never opens or downloads APKs.
Use --require-reviewed for production corpus claims so every row has an independently
reviewed label and a stable SHA-256 identifier.
"""
from pathlib import Path
import argparse, csv, json, statistics, sys, re

SHA256_RE=re.compile(r'^[a-fA-F0-9]{64}$')

def div(a,b): return a/b if b else 0.0

def p95(values):
    if not values: return 0.0
    v=sorted(values); return v[max(0,min(len(v)-1,int(round(.95*(len(v)-1)))))]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('csv',type=Path); ap.add_argument('--threshold',type=int,default=56)
    ap.add_argument('--min-detection-rate',type=float,default=None); ap.add_argument('--max-false-positive-rate',type=float,default=None)
    ap.add_argument('--min-precision',type=float,default=None); ap.add_argument('--min-family-accuracy',type=float,default=None)
    ap.add_argument('--min-samples',type=int,default=0); ap.add_argument('--min-malicious',type=int,default=0); ap.add_argument('--min-benign',type=int,default=0)
    ap.add_argument('--require-reviewed',action='store_true'); ap.add_argument('--json-out',type=Path); ap.add_argument('--allow-empty',action='store_true'); args=ap.parse_args()
    tp=tn=fp=fn=0; scan=[]; mem=[]; ft=fc=0; rows=0; reviewed_rows=0; source_groups=set(); malformed_review=[]
    with args.csv.open(newline='',encoding='utf-8') as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames or not {'expected_malicious','score'}.issubset(reader.fieldnames):
            print('BENCHMARK_GATE_FAILED required_columns=expected_malicious,score'); return 1
        for row in reader:
            if not any(str(v or '').strip() for v in row.values()): continue
            rows+=1
            exp=str(row['expected_malicious']).strip().lower() in {'1','true','yes'}; pred=int(row['score'])>=args.threshold
            if exp and pred: tp+=1
            elif exp: fn+=1
            elif pred: fp+=1
            else: tn+=1
            if str(row.get('scan_ms') or '').strip(): scan.append(float(row['scan_ms']))
            if str(row.get('peak_memory_mb') or '').strip(): mem.append(float(row['peak_memory_mb']))
            ef=str(row.get('expected_family') or '').strip().upper(); pf=str(row.get('predicted_family') or '').strip().upper()
            if exp and ef and pf:
                ft+=1; fc+=int(ef==pf)
            status=str(row.get('review_status') or '').strip().lower()
            sha=str(row.get('sample_sha256') or '').strip()
            if status == 'reviewed' and SHA256_RE.fullmatch(sha): reviewed_rows += 1
            elif args.require_reviewed: malformed_review.append(str(row.get('case_id') or rows))
            group=str(row.get('source_group') or '').strip()
            if group: source_groups.add(group)
    if rows==0:
        if args.allow_empty:
            print('BENCHMARK_EMPTY allowed=1'); return 0
        print('BENCHMARK_GATE_FAILED empty_corpus=1'); return 1
    malicious=tp+fn; benign=tn+fp
    metrics={
      'samples':rows,'malicious_samples':malicious,'benign_samples':benign,'tp':tp,'tn':tn,'fp':fp,'fn':fn,
      'detection_rate':div(tp,malicious),'false_positive_rate':div(fp,benign),'precision':div(tp,tp+fp),'accuracy':div(tp+tn,rows),
      'family_accuracy':div(fc,ft) if ft else None,'family_samples':ft,'reviewed_rows':reviewed_rows,'source_groups':len(source_groups),
      'scan_time_avg_ms':statistics.fmean(scan) if scan else None,'scan_time_p95_ms':p95(scan) if scan else None,
      'peak_memory_avg_mb':statistics.fmean(mem) if mem else None,'peak_memory_p95_mb':p95(mem) if mem else None,
    }
    print(f"BENCHMARK total={rows} malicious={malicious} benign={benign} tp={tp} tn={tn} fp={fp} fn={fn}")
    print(f"detection_rate={metrics['detection_rate']:.4f} false_positive_rate={metrics['false_positive_rate']:.4f} precision={metrics['precision']:.4f} accuracy={metrics['accuracy']:.4f}")
    if ft: print(f"family_accuracy={metrics['family_accuracy']:.4f} family_samples={ft}")
    if source_groups: print(f"source_groups={len(source_groups)} reviewed_rows={reviewed_rows}")
    if scan: print(f"scan_time_avg_ms={metrics['scan_time_avg_ms']:.2f} scan_time_p95_ms={metrics['scan_time_p95_ms']:.2f}")
    if mem: print(f"peak_memory_avg_mb={metrics['peak_memory_avg_mb']:.2f} peak_memory_p95_mb={metrics['peak_memory_p95_mb']:.2f}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True,exist_ok=True); args.json_out.write_text(json.dumps(metrics,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    failures=[]
    if args.require_reviewed and malformed_review: failures.append('unreviewed_or_missing_sha256')
    if rows < args.min_samples: failures.append('sample_count')
    if malicious < args.min_malicious: failures.append('malicious_count')
    if benign < args.min_benign: failures.append('benign_count')
    if args.min_detection_rate is not None and metrics['detection_rate'] < args.min_detection_rate: failures.append('detection_rate')
    if args.max_false_positive_rate is not None and metrics['false_positive_rate'] > args.max_false_positive_rate: failures.append('false_positive_rate')
    if args.min_precision is not None and metrics['precision'] < args.min_precision: failures.append('precision')
    if args.min_family_accuracy is not None and ft and metrics['family_accuracy'] < args.min_family_accuracy: failures.append('family_accuracy')
    if failures:
        detail = f" malformed_review_rows={malformed_review[:5]}" if malformed_review else ''
        print('BENCHMARK_GATE_FAILED metrics='+','.join(failures)+detail); return 1
    enforced=any([
        args.require_reviewed,args.min_samples,args.min_malicious,args.min_benign,
        args.min_detection_rate is not None,args.max_false_positive_rate is not None,
        args.min_precision is not None,args.min_family_accuracy is not None
    ])
    print('BENCHMARK_GATE_OK thresholds_enforced=1 reviewed_required='+str(int(args.require_reviewed)) if enforced else 'BENCHMARK_OK')
    return 0
if __name__=='__main__': sys.exit(main())
