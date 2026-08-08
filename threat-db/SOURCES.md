# Aman Security Phase 2 threat-intelligence seed

This folder contains cryptographic hashes only. It never contains malware samples.

| Threat reference | SHA-256 | Source note |
|---|---|---|
| 0000000001 | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | Harmless EICAR test signature |
| 2026070901 | e422e435a5abc7a2476dd7320954433f55e5f229abe0aaffa6b909d5bd3064c2 | MalwareBazaar Android banking sample |
| 2026070902 | 3408f14720eff6ff93e402f85cae60b17793eab8ccd501a17fa0eaa51a087f0d | MalwareBazaar Android dropper sample |
| 2022051901 | 0411d0ab80171bf29a481608d60d4ad55f193b9bbb64c0520df2e4da941ed031 | MalwareBazaar Android SMS/spyware sample |
| 2026052401 | ad9f39e6166a47ae16359777b607055198cda23f004d9d7b066e22c0d0cf1e6d | MalwareBazaar Android dropper sample |

Before publishing future updates, review source confidence and false-positive risk, increase the manifest serial, and sign the manifest with the offline private update key.

## Phase 5 link indicators

Phase 5 adds `url_indicators.csv`. The bundled URL rows are hashes of reserved `.test` values only, used as harmless test signatures. No live malicious URL is bundled. Future production URL/hash additions should come from reviewed high-confidence feeds, use exact URL hashes where broad host blocking could create false positives, and be signed with a higher manifest serial before publication.
