package com.aman.security.scanner

/**
 * Safe update canary. This is the SHA-256 of the harmless literal text
 * "AMAN-THREAT-DB-CANARY-v1"; it is never malware and is classified as TEST_SIGNATURE.
 */
object ThreatDbCanary {
    const val ID = "AMAN_DB_CANARY_0001"
    const val SHA256 = "99690a84a5003e207911b71281aa8aba067ac0378428575dfc2992f26fab0337"

    fun valid(signatures: Collection<ThreatSignature>): Boolean = signatures.any {
        it.sha256 == SHA256 && it.id == ID && it.classification == ScanClassification.TEST_SIGNATURE
    }
}
