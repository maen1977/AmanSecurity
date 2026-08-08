package com.aman.security.security

import com.aman.security.scanner.ScanClassification

object QuarantinePolicy {
    fun canOfferQuarantine(classification: ScanClassification, isExcluded: Boolean): Boolean {
        if (isExcluded) return false
        return classification != ScanClassification.NO_KNOWN_THREAT
    }
}
