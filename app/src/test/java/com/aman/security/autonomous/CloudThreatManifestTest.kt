package com.aman.security.autonomous

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudThreatManifestTest {
    @Test
    fun parsesOptionalSourceHealthMetadata() {
        val json = fixture(
            sources = """
                [{"name":"openphish","ok":true,"count":120,"detail":"feed"},
                 {"name":"threatfox","ok":true,"count":0,"detail":"skipped: ABUSECH_AUTH_KEY not configured"}]
            """.trimIndent()
        )

        val manifest = CloudThreatManifest.parse(json.toByteArray())

        assertEquals(2, manifest.sources.size)
        assertEquals("openphish", manifest.sources[0].name)
        assertTrue(manifest.sources[0].ok)
        assertEquals(120, manifest.sources[0].count)
        assertTrue(manifest.sources[1].detail.startsWith("skipped:"))
    }

    @Test
    fun rejectsUnsafeSourceMetadata() {
        val invalidName = fixture(
            sources = "[{\"name\":\"open-phish\",\"ok\":true,\"count\":1}]"
        )
        val oversizedDetail = fixture(
            sources = "[{\"name\":\"openphish\",\"detail\":\"${"x".repeat(241)}\"}]"
        )

        assertTrue(runCatching { CloudThreatManifest.parse(invalidName.toByteArray()) }.isFailure)
        assertTrue(runCatching { CloudThreatManifest.parse(oversizedDetail.toByteArray()) }.isFailure)
    }

    private fun fixture(sources: String = "[]"): String {
        val files = CloudThreatManifest.REQUIRED_FILES.joinToString(",") { name ->
            "\"$name\":{\"sha256\":\"${"a".repeat(64)}\",\"entries\":0,\"bytes\":0}"
        }
        return """
            {
              "schema":1,
              "serial":20260815120000,
              "version":"2026.08.15.1200",
              "generatedAt":"2026-08-15T12:00:00Z",
              "minAppVersionCode":44,
              "bundlePath":"aman-threat-db-20260815120000.zip",
              "bundleSha256":"${"b".repeat(64)}",
              "bundleBytes":1,
              "files":{$files},
              "sources":$sources
            }
        """.trimIndent()
    }
}
