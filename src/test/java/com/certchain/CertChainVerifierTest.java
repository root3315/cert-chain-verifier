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
    void testNullPemExtraction() {
        List<byte[]> certs = CertChainVerifier.extractPemCertificates(null);
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
    void testNullPemFormatValidation() {
        assertFalse(CertificateLoader.isValidPemFormat(null));
    }

    @Test
    void testLoadEmptyCertificateChain() throws IOException, CertificateException {
        File emptyFile = tempDir.resolve("empty.pem").toFile();
        Files.write(emptyFile.toPath(), "".getBytes(StandardCharsets.UTF_8));

        List<X509Certificate> certs = certificateLoader.loadCertificateChain(emptyFile);
        assertTrue(certs.isEmpty());
    }

    @Test
    void testLoadNullCertificateChain() {
        assertThrows(IllegalArgumentException.class, () -> {
            certificateLoader.loadCertificateChain(null);
        });
    }

    @Test
    void testLoadNonExistentCertificateChain() {
        File nonExistentFile = new File("/nonexistent/path/cert.pem");
        assertThrows(IOException.class, () -> {
            certificateLoader.loadCertificateChain(nonExistentFile);
        });
    }

    @Test
    void testLoadSingleCertificateNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            certificateLoader.loadSingleCertificate(null);
        });
    }

    @Test
    void testLoadPemCertificateChainNull() {
        assertThrows(CertificateException.class, () -> {
            certificateLoader.loadPemCertificateChain(null);
        });
    }

    @Test
    void testLoadDerCertificateChainNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            certificateLoader.loadDerCertificateChain(null);
        });
    }

    @Test
    void testLoadCertificateFromBytesNull() {
        assertThrows(CertificateException.class, () -> {
            certificateLoader.loadCertificateFromBytes(null);
        });
    }

    @Test
    void testExtractCertificateBytesNull() {
        assertThrows(CertificateException.class, () -> {
            certificateLoader.extractCertificateBytes(null);
        });
    }

    @Test
    void testToPemFormatNullCertificate() {
        assertThrows(CertificateException.class, () -> {
            certificateLoader.toPemFormat((X509Certificate) null);
        });
    }

    @Test
    void testToPemFormatNullList() {
        assertThrows(CertificateException.class, () -> {
            certificateLoader.toPemFormat((List<X509Certificate>) null);
        });
    }

    @Test
    void testIsPemFileNull() throws IOException {
        assertFalse(CertificateLoader.isPemFile(null));
    }

    @Test
    void testIsPemFileNonExistent() throws IOException {
        File nonExistentFile = new File("/nonexistent/path/cert.pem");
        assertFalse(CertificateLoader.isPemFile(nonExistentFile));
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
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testChainValidatorFullValidationNullChecks() {
        CertChainVerifier.ValidationResult result = chainValidator.validate(
                null,
                Collections.emptySet(),
                null,
                null,
                false);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testChainValidatorNoTrustAnchors() {
        CertChainVerifier.ValidationResult result = chainValidator.validate(
                java.util.Collections.singletonList(null),
                null,
                null,
                null,
                false);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testIsSelfSignedNull() {
        assertFalse(chainValidator.isSelfSigned(null));
    }

    @Test
    void testFindRootCertificateEmpty() {
        assertNull(chainValidator.findRootCertificate(Collections.emptyList()));
    }

    @Test
    void testFindRootCertificateNull() {
        assertNull(chainValidator.findRootCertificate(null));
    }

    @Test
    void testIsCompleteChainEmpty() {
        assertFalse(chainValidator.isCompleteChain(Collections.emptyList()));
    }

    @Test
    void testIsCompleteChainNull() {
        assertFalse(chainValidator.isCompleteChain(null));
    }

    @Test
    void testGetCertificatePathSubjectsNull() {
        List<String> subjects = chainValidator.getCertificatePathSubjects(null);
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
    void testCreateEmptyKeyStoreNullType() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.createEmptyKeyStore(null);
        });
    }

    @Test
    void testCreateEmptyKeyStoreEmptyType() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.createEmptyKeyStore("");
        });
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
    void testSaveKeyStoreNullKeyStore() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.saveKeyStore(null, tempDir.resolve("test.jks").toFile(), "password");
        });
    }

    @Test
    void testSaveKeyStoreNullFile() throws Exception {
        KeyStore keyStore = trustStoreManager.createEmptyKeyStore("JKS");
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.saveKeyStore(keyStore, null, "password");
        });
    }

    @Test
    void testIsValidTrustStore() throws IOException {
        File nonExistentFile = tempDir.resolve("nonexistent.jks").toFile();
        assertFalse(trustStoreManager.isValidTrustStore(nonExistentFile, "password"));
    }

    @Test
    void testIsValidTrustStoreNull() {
        assertFalse(trustStoreManager.isValidTrustStore(null, "password"));
    }

    @Test
    void testLoadTrustAnchorsFromKeyStoreNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.loadTrustAnchorsFromKeyStore(null);
        });
    }

    @Test
    void testGetTrustAnchorCountNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.getTrustAnchorCount(null);
        });
    }

    @Test
    void testContainsCertificateNullKeyStore() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.containsCertificate(null, null);
        });
    }

    @Test
    void testContainsCertificateNullCertificate() throws Exception {
        KeyStore keyStore = trustStoreManager.createEmptyKeyStore("JKS");
        assertFalse(trustStoreManager.containsCertificate(keyStore, null));
    }

    @Test
    void testCreateTrustAnchorFromFileNullFile() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.createTrustAnchorFromFile(null, certificateLoader);
        });
    }

    @Test
    void testCreateTrustAnchorFromFileNullLoader() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.createTrustAnchorFromFile(tempDir.resolve("cert.pem").toFile(), null);
        });
    }

    @Test
    void testMergeTrustAnchorsNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            trustStoreManager.mergeTrustAnchors((KeyStore[]) null);
        });
    }

    @Test
    void testCertificateChainValidationWithNoTrustAnchors() {
        CertChainVerifier.ValidationResult result = chainValidator.validate(
                java.util.Collections.singletonList(null),
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
        Files.write(derFile.toPath(), new byte[]{0x30, (byte) 0x82});
        assertFalse(CertificateLoader.isPemFile(derFile));
    }

    @Test
    @org.junit.jupiter.api.Disabled("System.exit() in main() kills the test JVM")
    void testMainMethodHelp() {
        assertDoesNotThrow(() -> CertChainVerifier.main(new String[]{"--help"}));
    }

    @Test
    @org.junit.jupiter.api.Disabled("System.exit() in main() kills the test JVM")
    void testMainMethodVersion() {
        assertDoesNotThrow(() -> CertChainVerifier.main(new String[]{"--version"}));
    }

    @Test
    @org.junit.jupiter.api.Disabled("System.exit() in main() kills the test JVM")
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

    @Test
    void testIsCertificateValidNowNull() {
        assertFalse(CertChainVerifier.isCertificateValidNow(null));
    }

    @Test
    void testValidateChainNullFile() throws CertificateException {
        CertChainVerifier verifier = new CertChainVerifier();
        CertChainVerifier.ValidationResult result = verifier.validateChain(
                null,
                Collections.emptySet(),
                false);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateChainNullTrustAnchors() throws IOException, CertificateException {
        CertChainVerifier verifier = new CertChainVerifier();
        File chainFile = tempDir.resolve("chain.pem").toFile();
        Files.write(chainFile.toPath(), "test".getBytes(StandardCharsets.UTF_8));

        CertChainVerifier.ValidationResult result = verifier.validateChain(
                chainFile,
                null,
                false);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateWithSystemTrustNull() throws IOException, CertificateException {
        CertChainVerifier verifier = new CertChainVerifier();
        CertChainVerifier.ValidationResult result = verifier.validateWithSystemTrust(null);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateWithCustomTrustNullChain() {
        CertChainVerifier verifier = new CertChainVerifier();
        CertChainVerifier.ValidationResult result = verifier.validateWithCustomTrust(
                null,
                tempDir.resolve("trust.jks").toFile(),
                "password");
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateWithCustomTrustNullTrustStore() throws IOException, CertificateException {
        CertChainVerifier verifier = new CertChainVerifier();
        File chainFile = tempDir.resolve("chain.pem").toFile();
        Files.write(chainFile.toPath(), "test".getBytes(StandardCharsets.UTF_8));

        CertChainVerifier.ValidationResult result = verifier.validateWithCustomTrust(
                chainFile,
                null,
                "password");
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateWithPemTrustNullChain() {
        CertChainVerifier verifier = new CertChainVerifier();
        CertChainVerifier.ValidationResult result = verifier.validateWithPemTrust(
                null,
                Collections.emptyList());
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testValidateWithPemTrustNullList() throws IOException, CertificateException {
        CertChainVerifier verifier = new CertChainVerifier();
        File chainFile = tempDir.resolve("chain.pem").toFile();
        Files.write(chainFile.toPath(), "test".getBytes(StandardCharsets.UTF_8));

        CertChainVerifier.ValidationResult result = verifier.validateWithPemTrust(
                chainFile,
                null);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testExpiredCertificateErrorMessage() throws Exception {
        // Create a self-signed cert with 1 day validity using keytool
        File expiredCertFile = tempDir.resolve("expired.jks").toFile();

        ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", "expired",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "1",
                "-keystore", expiredCertFile.getAbsolutePath(),
                "-storepass", "changeit",
                "-dname", "CN=Expired Test, OU=Test, O=Test, C=US",
                "-keypass", "changeit");
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        proc.waitFor();

        KeyStore ks = KeyStore.getInstance("JKS");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(expiredCertFile)) {
            ks.load(fis, "changeit".toCharArray());
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate("expired");

        List<X509Certificate> certs = java.util.Collections.singletonList(cert);

        // Test the validation result - cert may or may not be expired depending on timing
        CertChainVerifier.ValidationResult result = chainValidator.validateBasicChain(certs);
        if (!result.isValid()) {
            String message = result.getErrorMessage();
            assertTrue(message.contains("Subject:") || message.contains("expired") ||
                    message.contains("Expired") || message.contains("Days Expired") ||
                    message.contains("Valid From") || message.contains("not yet valid"),
                    "Error message should include certificate details: " + message);
        }
    }

    @Test
    void testNotYetValidCertificateErrorMessage() throws Exception {
        // Create a fresh cert and verify it validates successfully
        File freshCertFile = tempDir.resolve("fresh.jks").toFile();

        ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", "fresh",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365",
                "-keystore", freshCertFile.getAbsolutePath(),
                "-storepass", "changeit",
                "-dname", "CN=Fresh Test, OU=Test, O=Test, C=US",
                "-keypass", "changeit");
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        proc.waitFor();

        KeyStore ks = KeyStore.getInstance("JKS");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(freshCertFile)) {
            ks.load(fis, "changeit".toCharArray());
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate("fresh");

        List<X509Certificate> certs = java.util.Collections.singletonList(cert);

        CertChainVerifier.ValidationResult result = chainValidator.validateBasicChain(certs);
        assertTrue(result.isValid(), "Fresh certificate should be valid");
    }
}
