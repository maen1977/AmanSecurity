package com.aman.security.autonomous

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudThreatManifestTest {
    @Test
    fun parsesOptionalSourceHealthMetadata() {
        val json = fixture().put(
            "sources",
            JSONArray()
                .put(JSONObject().put("name", "openphish").put("ok", true).put("count", 120).put("detail", "feed"))
                .put(JSONObject().put("name", "threatfox").put("ok", true).put("count", 0).put("detail", "skipped: ABUSECH_AUTH_KEY not configured"))
        )

        val manifest = CloudThreatManifest.parse(json.toString().toByteArray())

        assertEquals(2, manifest.sources.size)
        assertEquals("openphish", manifest.sources[0].name)
        assertTrue(manifest.sources[0].ok)
        assertEquals(120, manifest.sources[0].count)
        assertTrue(manifest.sources[1].detail.startsWith("skipped:"))
    }

    @Test
    fun rejectsUnsafeSourceMetadata() {
        val invalidName = fixture().put(
            "sources",
            JSONArray().put(JSONObject().put("name", "open-phish").put("ok", true).put("count", 1))
        )
        val oversizedDetail = fixture().put(
            "sources",
            JSONArray().put(JSONObject().put("name", "openphish").put("detail", "x".repeat(241)))
        )

        assertTrue(runCatching { CloudThreatManifest.parse(invalidName.toString().toByteArray()) }.isFailure)
        assertTrue(runCatching { CloudThreatManifest.parse(oversizedDetail.toString().toByteArray()) }.isFailure)
    }

    private fun fixture(): JSONObject {
        val files = JSONObject()
        CloudThreatManifest.REQUIRED_FILES.forEach { name ->
            files.put(
                name,
                JSONObject()
                    .put("sha256", "a".repeat(64))
                    .put("entries", 0)
                    .put("bytes", 0)
            )
        }
        return JSONObject()
            .put("schema", 1)
            .put("serial", 20260815120000L)
            .put("version", "2026.08.15.1200")
            .put("generatedAt", "2026-08-15T12:00:00Z")
            .put("minAppVersionCode", 44)
            .put("bundlePath", "aman-threat-db-20260815120000.zip")
            .put("bundleSha256", "b".repeat(64))
            .put("bundleBytes", 1)
            .put("files", files)
    }
}
