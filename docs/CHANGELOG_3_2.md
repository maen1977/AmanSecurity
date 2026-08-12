# Aman Security 3.2.0 — Lightweight Attack Detection Center

- Adds a compact on-device Attack Detection Center that correlates the bounded local protection timeline from malware scans, Downloads protection, Web Shield, privileged-access changes, banking guard, and security audits.
- A blocked malicious domain is shown as a **review/watch** signal, not proof that the phone was compromised.
- Malware/high-risk app or file detections, high-priority privilege changes, and Banking Guard BLOCK events become **critical local attack indicators**.
- The persistent protection notification now reflects recent critical/watch status and opens the Protection Center for review.
- No new worker, polling loop, packet inspection engine, cloud backend, or always-on scanner was added for the Attack Detection Center.
- Enabling protection no longer immediately launches protected-folder and Downloads catch-up scans. Periodic catch-up jobs receive initial delays; new apps and new Downloads remain event-driven and immediate.
- Adds pure policy regression tests so a blocked web threat is not mislabeled as a confirmed compromise.
