#!/usr/bin/env python3
from pathlib import Path
import re, xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
FILES={
    'en':ROOT/'app/src/main/res/values/strings.xml',
    'ar':ROOT/'app/src/main/res/values-ar/strings.xml',
}
SPEC=re.compile(r'%(?:(\d+)\$)?([sdfox])')

def load(path):
    root=ET.parse(path).getroot()
    return {e.attrib['name']:''.join(e.itertext()) for e in root if e.tag=='string'}

def signature(text):
    return [(m.group(1) or '',m.group(2)) for m in SPEC.finditer(text.replace('%%',''))]

strings={k:load(v) for k,v in FILES.items()}
errors=[]
for key in sorted(strings['en']):
    en_sig=signature(strings['en'][key]); ar_sig=signature(strings['ar'][key])
    if en_sig != ar_sig: errors.append(f'{key}:en={en_sig}:ar={ar_sig}')
    for locale,sig in [('en',en_sig),('ar',ar_sig)]:
        if len(sig)>1 and any(not pos for pos,_ in sig): errors.append(f'{key}:{locale}:non_positional_multi_arg')
if errors:
    raise SystemExit('ANDROID_STRING_FORMAT_GATE_FAILED '+ ' | '.join(errors[:20]))
print(f'ANDROID_STRING_FORMAT_GATE_OK strings={len(strings["en"])} formatted={sum(bool(signature(v)) for v in strings["en"].values())} locale_type_parity=1')
