#!/usr/bin/env python3
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
EN = ROOT / "app/src/main/res/values/strings.xml"
AR = ROOT / "app/src/main/res/values-ar/strings.xml"
LAYOUT_DIR = ROOT / "app/src/main/res/layout"
KOTLIN_DIR = ROOT / "app/src/main/java"

ARABIC_RE = re.compile(r"[\u0600-\u06FF]")
LATIN_WORD_RE = re.compile(r"\b[A-Za-z]{2,}(?:-[A-Za-z0-9]+)?\b")
ALLOWED_AR_LATIN = {"SHA-256", "APK"}
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def load_strings(path: Path):
    root = ET.parse(path).getroot()
    return {e.attrib["name"]: "".join(e.itertext()) for e in root.findall("string")}

def fail(message: str, errors: list[str]):
    errors.append(message)

def main():
    errors: list[str] = []
    en = load_strings(EN)
    ar = load_strings(AR)

    if set(en) != set(ar):
        missing_ar = sorted(set(en) - set(ar))
        missing_en = sorted(set(ar) - set(en))
        if missing_ar:
            fail(f"Arabic missing keys: {missing_ar}", errors)
        if missing_en:
            fail(f"English missing keys: {missing_en}", errors)

    PLACEHOLDER_RE = re.compile(r"%(?:\d+\$)?[sdif]")
    for key in sorted(set(en) & set(ar)):
        en_placeholders = sorted(PLACEHOLDER_RE.findall(en[key]))
        ar_placeholders = sorted(PLACEHOLDER_RE.findall(ar[key]))
        if en_placeholders != ar_placeholders:
            fail(f"Placeholder mismatch for '{key}': en={en_placeholders} ar={ar_placeholders}", errors)

    for key, text in en.items():
        if ARABIC_RE.search(text):
            fail(f"Arabic script leaked into English key '{key}': {text}", errors)

    for key, text in ar.items():
        latin_words = {w.upper() for w in LATIN_WORD_RE.findall(text)}
        bad = sorted(latin_words - ALLOWED_AR_LATIN)
        if bad:
            fail(f"Unapproved Latin word(s) in Arabic key '{key}': {bad}", errors)

    for layout in LAYOUT_DIR.glob("*.xml"):
        tree = ET.parse(layout)
        for elem in tree.iter():
            for attr in ("text", "hint", "contentDescription"):
                value = elem.attrib.get(ANDROID_NS + attr)
                if value and not value.startswith("@") and value not in ("",):
                    fail(f"Hardcoded UI text in {layout.name}: android:{attr}={value}", errors)

    source_patterns = [
        re.compile(r"\.setText\(\s*\""),
        re.compile(r"Toast\.makeText\([^\n]*\""),
        re.compile(r"setTitle\(\s*\""),
    ]
    for source in KOTLIN_DIR.rglob("*.kt"):
        text = source.read_text(encoding="utf-8")
        for pattern in source_patterns:
            if pattern.search(text):
                fail(f"Possible hardcoded user-facing string in {source.relative_to(ROOT)}", errors)

    if errors:
        print("LOCALIZATION_GATE_FAILED")
        for item in errors:
            print(" -", item)
        return 1

    print(f"LOCALIZATION_GATE_OK keys={len(en)} languages=en,ar hardcoded_ui=0")
    return 0

if __name__ == "__main__":
    sys.exit(main())
