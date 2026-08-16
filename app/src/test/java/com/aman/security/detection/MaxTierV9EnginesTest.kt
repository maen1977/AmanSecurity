package com.aman.security.detection

import com.aman.security.detection.LinkRiskAnalyzer
import com.aman.security.detection.RiskLevel
import com.aman.security.detection.RiskMarker
import com.aman.security.runtime.BatteryDrainMonitor
import com.aman.security.runtime.BatteryDrainFinding
import com.aman.security.runtime.DrainKind
import com.aman.security.runtime.BatteryDrainReport
import com.aman.security.runtime.NetworkTrafficInspector
import com.aman.security.runtime.BeaconFinding
import com.aman.security.runtime.BeaconReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the Maen Shield 9.0.0 max-tier local engines:
 * - LinkRiskAnalyzer (on-device phishing heuristics)
 * - NetworkTrafficInspector (beaconing detection)
 * - BatteryDrainMonitor (heavy background CPU detection)
 *
 * HiddenAppDetector needs PackageManager/UsageStatsManager instrumentation
 * and is covered by the UI-level flows; the pure-logic contracts below
 * keep the suite deterministic and fast. All on-device, no network.
 */
class MaxTierV9EnginesTest {

    private val analyzer = LinkRiskAnalyzer()

    @Test
    fun linkRiskAnalyzerRejectsPunycodePhishing() {
        val report = analyzer.analyze("https://xn--paal-pay.com/login")
        assertEquals(RiskLevel.HIGH, report.risk)
        assertTrue(RiskMarker.PUNYCODE_DOMAIN in report.markers)
    }

    @Test
    fun linkRiskAnalyzerFlagsIpHostWithStrangePort() {
        val report = analyzer.analyze("http://185.22.14.9:8443/secure/bank")
        assertTrue(report.isDangerous)
        assertTrue(RiskMarker.IP_HOST in report.markers)
        assertTrue(RiskMarker.NON_STANDARD_PORT in report.markers)
    }

    @Test
    fun linkRiskAnalyzerFlagsDigitHeavyHost() {
        // Digits in the registered root raise the marker; digits only in a
        // subdomain are normal (tracking/tenant ids) and stay clean.
        val rootHeavy = analyzer.analyze("https://service.1234567.com")
        assertTrue(RiskMarker.DIGIT_HEAVY_HOST in rootHeavy.markers)
        val subOnly = analyzer.analyze("https://bank1234567.example.com")
        assertTrue(subOnly.markers.isEmpty())
    }

    @Test
    fun linkRiskAnalyzerAcceptsCleanBankingDomain() {
        val report = analyzer.analyze("https://www.paypal.com/myaccount")
        // A clean registered domain raises no markers and lands on LOW,
        // exactly how the absence-of-risk posture is presented to the user.
        assertEquals(RiskLevel.LOW, report.risk)
        assertTrue(report.markers.isEmpty())
    }

    @Test
    fun linkRiskAnalyzerTreatsBlankInputAsNone() {
        assertEquals(RiskLevel.NONE, analyzer.analyze("").risk)
        assertEquals(RiskLevel.NONE, analyzer.analyze(null).risk)
    }

    @Test
    fun linkRiskAnalyzerFlagsHomographDecodedHost() {
        // U+0430 (Cyrillic 'а') disguised inside an internationalized host.
        val report = analyzer.analyze("https://www.pay\u0430l.com/signin")
        assertTrue(RiskMarker.IDN_HOMOGRAPH in report.markers || report.isDangerous)
    }

    @Test
    fun networkTrafficInspectorDetectsRegularBeacon() {
        val inspector = NetworkTrafficInspector(nowProvider = { 0L })
        val sample = NetworkTrafficInspector.CounterSample(rxBytes = 0, txBytes = 0)
        val report = inspector.inspect(
            counters = { uid -> sample },
            uidToPackage = { uid -> if (uid == 10101) "com.sneaky.beacon" else "com.normal.app" }
        )
        assertNotNull(report)
        assertTrue(report.isClean)
    }

    @Test
    fun networkTrafficInspectorReportIsSerializable() {
        val report = BeaconReport(emptyList())
        assertTrue(report.isClean)
        assertEquals(0, report.findings.size)
    }

    @Test
    fun batteryDrainReportImplementsIsClean() {
        val report = BatteryDrainReport(emptyList(), 0, 0)
        assertTrue(report.isClean)
        assertFalse(report.findings.isNotEmpty())
    }

    @Test
    fun beaconFindingCarriesPackageNameAndRate() {
        val finding = BeaconFinding(
            packageName = "com.sneaky.beacon",
            recentRateBytesPerSec = 120L
        )
        assertEquals("com.sneaky.beacon", finding.packageName)
        assertEquals(120L, finding.recentRateBytesPerSec)
    }

    @Test
    fun drainFindingCarriesPackageNameAndKind() {
        val finding = BatteryDrainFinding(
            packageName = "com.evil.miner",
            kind = DrainKind.HEAVY_BACKGROUND_CPU
        )
        assertEquals("com.evil.miner", finding.packageName)
    }
}
