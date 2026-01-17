package com.certchain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Certificate Chain Verifier components.
 */
class CertChainVerifierTest {

    @TempDir
    Path tempDir;

    private CertificateLoader certificateLoader;
    private ChainValidator chainValidator;
    private TrustStoreManager trustStoreManager;

    @BeforeEach
    void setUp() throws CertificateException {
        certificateLoader = new CertificateLoader(
                java.security.cert.CertificateFactory.getInstance("X.509"));
        chainValidator = new ChainValidator();
        trustStoreManager = new TrustStoreManager();
    }

    @Test
    void testPemCertificateExtraction() throws CertificateException {
        String pemContent = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n" +
                "c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n" +
                "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96WzE5mfUEQNnvLp6Jh\n" +
                "m5s3d8x9K2E4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9EA\n" +
                "AgMBAAGjUzBRMB0GA1UdDgQWBBQTest1234567890abcdefghijk==\n" +
                "-----END CERTIFICATE-----";

        List<byte[]> certs = CertChainVerifier.extractPemCertificates(pemContent);
        assertEquals(1, certs.size());
        assertNotNull(certs.get(0));
        assertTrue(certs.get(0).length > 0);
    }

    @Test
    void testEmptyPemExtraction() {
        List<byte[]> certs = CertChainVerifier.extractPemCertificates("no certificates here");
        assertTrue(certs.isEmpty());
    }

    @Test
    void testMultiplePemCertificates() throws CertificateException {
        String pemContent = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n" +
                "c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n" +
                "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96WzE5mfUEQNnvLp6Jh\n" +
                "m5s3d8x9K2E4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9EA\n" +
                "AgMBAAGjUzBRMB0GA1UdDgQWBBQTest1234567890abcdefghijk==\n" +
                "-----END CERTIFICATE-----\n" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n" +
                "c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n" +
                "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96WzE5mfUEQNnvLp6Jh\n" +
                "m5s3d8x9K2E4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9EB\n" +
                "AgMBAAGjUzBRMB0GA1UdDgQWBBQTest0987654321zyxwvutsrqponm==\n" +
                "-----END CERTIFICATE-----";

        List<byte[]> certs = CertChainVerifier.extractPemCertificates(pemContent);
        assertEquals(2, certs.size());
    }

    @Test
    void testPemFormatValidation() {
        String validPem = "-----BEGIN CERTIFICATE-----\n" +
                "SGVsbG8gV29ybGQ=\n" +
                "-----END CERTIFICATE-----";
        assertTrue(CertificateLoader.isValidPemFormat(validPem));

        String invalidPem = "-----BEGIN CERTIFICATE-----\n" +
                "Invalid!!!\n" +
                "-----END CERTIFICATE-----";
        assertFalse(CertificateLoader.isValidPemFormat(invalidPem));

        String noHeader = "SGVsbG8gV29ybGQ=\n" +
                "-----END CERTIFICATE-----";
        assertFalse(CertificateLoader.isValidPemFormat(noHeader));
    }

    @Test
    void testLoadEmptyCertificateChain() throws IOException {
        File emptyFile = tempDir.resolve("empty.pem").toFile();
        Files.write(emptyFile.toPath(), "".getBytes(StandardCharsets.UTF_8));

        List<X509Certificate> certs = certificateLoader.loadCertificateChain(emptyFile);
        assertTrue(certs.isEmpty());
    }

    @Test
    void testChainValidatorEmptyChain() {
        CertChainVerifier.ValidationResult result = chainValidator.validateBasicChain(
                Collections.emptyList());
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("empty"));
    }

    @Test
    void testChainValidatorNullChain() {
        CertChainVerifier.ValidationResult result = chainValidator.validateBasicChain(null);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("empty or null"));
    }

    @Test
    void testIsSelfSigned() {
        assertFalse(chainValidator.isSelfSigned(null));
    }

    @Test
    void testFindRootCertificateEmpty() {
        assertNull(chainValidator.findRootCertificate(Collections.emptyList()));
    }

    @Test
    void testIsCompleteChainEmpty() {
        assertFalse(chainValidator.isCompleteChain(Collections.emptyList()));
    }

    @Test
    void testGetCertificatePathSubjectsEmpty() {
        List<String> subjects = chainValidator.getCertificatePathSubjects(
                Collections.emptyList());
        assertTrue(subjects.isEmpty());
    }

    @Test
    void testCreateEmptyKeyStore() throws Exception {
        KeyStore keyStore = trustStoreManager.createEmptyKeyStore("JKS");
        assertNotNull(keyStore);
        assertEquals(0, trustStoreManager.getTrustAnchorCount(keyStore));
    }

    @Test
    void testCreateEmptyPKCS12KeyStore() throws Exception {
        KeyStore keyStore = trustStoreManager.createEmptyKeyStore("PKCS12");
        assertNotNull(keyStore);
    }

    @Test
    void testSystemTrustStorePath() {
        String path = trustStoreManager.getSystemTrustStorePath();
        if (path != null) {
            assertTrue(path.endsWith("cacerts"));
        }
    }

    @Test
    void testValidationResultSuccess() {
        CertChainVerifier.ValidationResult result = 
                CertChainVerifier.ValidationResult.success("Test success message");
        assertTrue(result.isValid());
        assertEquals("Test success message", result.getSuccessMessage());
        assertNull(result.getErrorMessage());
    }

    @Test
    void testValidationResultFailure() {
        CertChainVerifier.ValidationResult result = 
                CertChainVerifier.ValidationResult.failure("Test error message");
        assertFalse(result.isValid());
        assertEquals("Test error message", result.getErrorMessage());
        assertNull(result.getSuccessMessage());
    }

    @Test
    void testToPemFormat() throws Exception {
        String testBase64 = "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n" +
                "c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n" +
                "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96WzE5mfUEQNnvLp6Jh\n" +
                "m5s3d8x9K2E4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9EA\n" +
                "AgMBAAGjUzBRMB0GA1UdDgQWBBQTest1234567890abcdefghijk==";
        byte[] certBytes = Base64.getDecoder().decode(testBase64);
        X509Certificate cert = certificateLoader.loadCertificateFromBytes(certBytes);
        
        String pem = certificateLoader.toPemFormat(cert);
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.contains("-----END CERTIFICATE-----"));
    }

    @Test
    void testExtractCertificateBytes() throws CertificateException {
        String pemContent = "-----BEGIN CERTIFICATE-----\n" +
                "SGVsbG8gV29ybGQ=\n" +
                "-----END CERTIFICATE-----";

        List<byte[]> certBytes = certificateLoader.extractCertificateBytes(pemContent);
        assertEquals(1, certBytes.size());
        assertArrayEquals("Hello World".getBytes(StandardCharsets.UTF_8), certBytes.get(0));
    }

    @Test
    void testKeyStoreCreation() throws Exception {
        File jksFile = tempDir.resolve("test.jks").toFile();
        KeyStore keyStore = trustStoreManager.createEmptyKeyStore("JKS");
        trustStoreManager.saveKeyStore(keyStore, jksFile, "password");
        assertTrue(jksFile.exists());

        File p12File = tempDir.resolve("test.p12").toFile();
        KeyStore pkcs12Store = trustStoreManager.createEmptyKeyStore("PKCS12");
        trustStoreManager.saveKeyStore(pkcs12Store, p12File, "password");
        assertTrue(p12File.exists());
    }

    @Test
    void testIsValidTrustStore() throws IOException {
        File nonExistentFile = tempDir.resolve("nonexistent.jks").toFile();
        assertFalse(trustStoreManager.isValidTrustStore(nonExistentFile, "password"));
    }

    @Test
    void testCertificateChainValidationWithNoTrustAnchors() {
        CertChainVerifier.ValidationResult result = chainValidator.validate(
                Collections.emptyList(),
                Collections.emptySet(),
                null,
                null,
                false);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("No trust anchors"));
    }

    @Test
    void testPemFileDetection() throws IOException {
        File pemFile = tempDir.resolve("test.pem").toFile();
        String pemContent = "-----BEGIN CERTIFICATE-----\n" +
                "SGVsbG8gV29ybGQ=\n" +
                "-----END CERTIFICATE-----";
        try (FileWriter writer = new FileWriter(pemFile)) {
            writer.write(pemContent);
        }
        assertTrue(CertificateLoader.isPemFile(pemFile));

        File derFile = tempDir.resolve("test.der").toFile();
        Files.write(derFile.toPath(), new byte[]{0x30, 0x82});
        assertFalse(CertificateLoader.isPemFile(derFile));
    }

    @Test
    void testMainMethodHelp() {
        assertDoesNotThrow(() -> CertChainVerifier.main(new String[]{"--help"}));
    }

    @Test
    void testMainMethodVersion() {
        assertDoesNotThrow(() -> CertChainVerifier.main(new String[]{"--version"}));
    }

    @Test
    void testMainMethodNoArgs() {
        assertDoesNotThrow(() -> {
            try {
                CertChainVerifier.main(new String[]{});
            } catch (RuntimeException e) {
                if (!"exit".equals(e.getMessage())) {
                    throw e;
                }
            }
        });
    }
}
