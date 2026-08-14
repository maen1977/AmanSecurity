package com.aman.security.security

import com.aman.security.scanner.ScanClassification

object QuarantinePolicy {
    fun canOfferQuarantine(classification: ScanClassification, isExcluded: Boolean): Boolean {
        if (isExcluded) return false
        return classification != ScanClassification.NO_KNOWN_THREAT
    }

    /**
     * Automatic action is deliberately stricter than the manual quarantine button.
     * Only an exact, non-excluded signature may remove a downloaded source file.
     */
    fun shouldAutoQuarantine(classification: ScanClassification, isExcluded: Boolean): Boolean =
        !isExcluded && classification == ScanClassification.KNOWN_THREAT
}
