from pathlib import Path
import sys
root=Path(__file__).resolve().parents[1]
dir=root/'.github/workflows'
files=sorted(p.relative_to(root).as_posix() for p in dir.glob('*') if p.is_file() and p.suffix.lower() in {'.yml','.yaml'})
expected=['.github/workflows/main.yml']
if files!=expected:
    print('SINGLE_WORKFLOW_GATE_FAILED'); print('Found:',*files,sep='\n - '); sys.exit(1)
w=(root/expected[0]).read_text(encoding='utf-8')
checks={
 'auto_push_main':'push:' in w and 'branches: [ "main" ]' in w,
 'scheduled_refresh':'schedule:' in w and '17 */6 * * *' in w,
 'manual':'workflow_dispatch:' in w,
 'concurrency':'cancel-in-progress: true' in w,
 'single_pipeline_name':'name: Aman Security Pipeline' in w,
}
bad=[k for k,v in checks.items() if not v]
if bad:
    print('SINGLE_WORKFLOW_GATE_FAILED',','.join(bad)); sys.exit(1)
print('SINGLE_WORKFLOW_GATE_OK count=1 trigger=push_main+schedule_6h+manual concurrency_cancel=1')
