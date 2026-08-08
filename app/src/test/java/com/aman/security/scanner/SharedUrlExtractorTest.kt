package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SharedUrlExtractorTest {
    @Test
    fun extractsFirstWebLinkFromSharedText() {
        assertEquals(
            "https://example.com/login",
            SharedUrlExtractor.firstCandidate("Please check https://example.com/login before opening it")
        )
    }

    @Test
    fun keepsSingleDomainCandidateForNormalizer() {
        assertEquals("example.com", SharedUrlExtractor.firstCandidate("example.com"))
    }

    @Test
    fun ignoresPlainSentenceWithoutWebLink() {
        assertNull(SharedUrlExtractor.firstCandidate("This message has no link"))
    }
}
