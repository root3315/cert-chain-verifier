package com.certchain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * X.509 Certificate Chain Verifier
 * 
 * A command-line tool for validating X.509 certificate chains with customizable
 * trust anchors. Supports PEM and DER certificate formats.
 */
public class CertChainVerifier {

    private static final String PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_CERT_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(
            PEM_CERT_HEADER + "(.*?)" + PEM_CERT_FOOTER, Pattern.DOTALL);

    private final CertificateFactory certificateFactory;
    private final CertPathValidator certPathValidator;
    private final CertificateLoader certificateLoader;
    private final ChainValidator chainValidator;
    private final TrustStoreManager trustStoreManager;

    public CertChainVerifier() throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        this.certPathValidator = CertPathValidator.getInstance("PKIX");
        this.certificateLoader = new CertificateLoader(certificateFactory);
        this.chainValidator = new ChainValidator();
        this.trustStoreManager = new TrustStoreManager();
    }

    /**
     * Validates a certificate chain against a set of trust anchors.
     *
     * @param chainFile the file containing the certificate chain (PEM or DER)
     * @param trustAnchors the set of trusted root certificates
     * @param checkRevocation whether to check certificate revocation
     * @return ValidationResult containing the validation status and details
     */
    public ValidationResult validateChain(File chainFile, Set<TrustAnchor> trustAnchors,
                                          boolean checkRevocation) {
        try {
            List<X509Certificate> certificates = certificateLoader.loadCertificateChain(chainFile);
            
            if (certificates.isEmpty()) {
                return ValidationResult.failure("No certificates found in the chain file");
            }

            System.out.println("Loaded " + certificates.size() + " certificate(s) from chain");
            printCertificateInfo(certificates);

            return chainValidator.validate(certificates, trustAnchors, certPathValidator,
                    certificateFactory, checkRevocation);

        } catch (CertificateException e) {
            return ValidationResult.failure("Failed to parse certificates: " + e.getMessage());
        } catch (IOException e) {
            return ValidationResult.failure("Failed to read chain file: " + e.getMessage());
        }
    }

    /**
     * Validates a certificate chain using the system default trust store.
     *
     * @param chainFile the file containing the certificate chain
     * @return ValidationResult containing the validation status and details
     */
    public ValidationResult validateWithSystemTrust(File chainFile) {
        try {
            Set<TrustAnchor> systemTrustAnchors = trustStoreManager.loadSystemTrustAnchors();
            System.out.println("Loaded " + systemTrustAnchors.size() + " system trust anchors");
            return validateChain(chainFile, systemTrustAnchors, false);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            return ValidationResult.failure("Failed to load system trust store: " + e.getMessage());
        }
    }

    /**
     * Validates a certificate chain using a custom trust store file.
     *
     * @param chainFile the file containing the certificate chain
     * @param trustStoreFile the trust store file (JKS or PKCS12)
     * @param trustStorePassword the trust store password
     * @return ValidationResult containing the validation status and details
     */
    public ValidationResult validateWithCustomTrust(File chainFile, File trustStoreFile,
                                                     String trustStorePassword) {
        try {
            Set<TrustAnchor> customTrustAnchors = trustStoreManager.loadTrustAnchorsFromFile(
                    trustStoreFile, trustStorePassword);
            System.out.println("Loaded " + customTrustAnchors.size() + " custom trust anchors");
            return validateChain(chainFile, customTrustAnchors, false);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            return ValidationResult.failure("Failed to load custom trust store: " + e.getMessage());
        }
    }

    /**
     * Validates a certificate chain using PEM-encoded trust anchors.
     *
     * @param chainFile the file containing the certificate chain
     * @param trustAnchorFiles list of files containing PEM-encoded trust anchors
     * @return ValidationResult containing the validation status and details
     */
    public ValidationResult validateWithPemTrust(File chainFile, List<File> trustAnchorFiles) {
        try {
            Set<TrustAnchor> pemTrustAnchors = new HashSet<>();
            for (File trustFile : trustAnchorFiles) {
                List<X509Certificate> trustCerts = certificateLoader.loadCertificateChain(trustFile);
                for (X509Certificate cert : trustCerts) {
                    pemTrustAnchors.add(new TrustAnchor(cert, null));
                }
            }
            System.out.println("Loaded " + pemTrustAnchors.size() + " PEM trust anchors");
            return validateChain(chainFile, pemTrustAnchors, false);
        } catch (CertificateException | IOException e) {
            return ValidationResult.failure("Failed to load PEM trust anchors: " + e.getMessage());
        }
    }

    private void printCertificateInfo(List<X509Certificate> certificates) {
        System.out.println("\nCertificate Chain Details:");
        System.out.println("==========================");
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            System.out.println("\n[" + i + "] " + cert.getSubjectX500Principal().getName());
            System.out.println("    Issuer: " + cert.getIssuerX500Principal().getName());
            System.out.println("    Serial: " + cert.getSerialNumber().toString(16).toUpperCase());
            System.out.println("    Valid From: " + cert.getNotBefore());
            System.out.println("    Valid To: " + cert.getNotAfter());
            System.out.println("    Version: " + cert.getVersion());
            System.out.println("    Signature Algorithm: " + cert.getSigAlgName());
            
            if (i == 0) {
                System.out.println("    Type: End Entity Certificate");
            } else if (i == certificates.size() - 1) {
                System.out.println("    Type: Root Certificate");
            } else {
                System.out.println("    Type: Intermediate Certificate");
            }
        }
        System.out.println();
    }

    /**
     * Extracts PEM-encoded certificates from a string.
     *
     * @param pemContent the PEM-encoded certificate content
     * @return list of Base64-encoded certificate bytes
     */
    public static List<byte[]> extractPemCertificates(String pemContent) {
        List<byte[]> certificates = new ArrayList<>();
        Matcher matcher = PEM_PATTERN.matcher(pemContent);
        while (matcher.find()) {
            String base64Cert = matcher.group(1).replaceAll("\\s+", "");
            certificates.add(Base64.getDecoder().decode(base64Cert));
        }
        return certificates;
    }

    /**
     * Checks if a certificate is currently valid based on its validity period.
     *
     * @param certificate the certificate to check
     * @return true if the certificate is within its validity period
     */
    public static boolean isCertificateValidNow(X509Certificate certificate) {
        Date now = new Date();
        try {
            certificate.checkValidity(now);
            return true;
        } catch (CertificateException e) {
            return false;
        }
    }

    /**
     * Prints usage information for the command-line tool.
     */
    public static void printUsage() {
        System.out.println("X.509 Certificate Chain Verifier");
        System.out.println("================================");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar cert-chain-verifier.jar <command> [options]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  validate <chain.pem>                    Validate chain against system trust");
        System.out.println("  validate-with-store <chain.pem> <truststore> [password]");
        System.out.println("                                          Validate with custom trust store");
        System.out.println("  validate-with-pem <chain.pem> <anchor1.pem> [anchor2.pem ...]");
        System.out.println("                                          Validate with PEM trust anchors");
        System.out.println("  info <cert.pem>                         Display certificate information");
        System.out.println("  extract <chain.pem>                     Extract individual certificates");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --help, -h                              Show this help message");
        System.out.println("  --version, -v                           Show version information");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar cert-chain-verifier.jar validate server-chain.pem");
        System.out.println("  java -jar cert-chain-verifier.jar validate-with-store chain.pem trust.jks password");
        System.out.println("  java -jar cert-chain-verifier.jar validate-with-pem chain.pem root-ca.pem");
    }

    /**
     * Main entry point for the certificate chain verifier.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        if ("--help".equals(args[0]) || "-h".equals(args[0])) {
            printUsage();
            System.exit(0);
        }

        if ("--version".equals(args[0]) || "-v".equals(args[0])) {
            System.out.println("Certificate Chain Verifier version 1.0.0");
            System.exit(0);
        }

        String command = args[0];
        
        try {
            CertChainVerifier verifier = new CertChainVerifier();
            ValidationResult result;

            switch (command) {
                case "validate":
                    if (args.length < 2) {
                        System.err.println("Error: Missing chain file argument");
                        printUsage();
                        System.exit(1);
                    }
                    result = verifier.validateWithSystemTrust(new File(args[1]));
                    break;

                case "validate-with-store":
                    if (args.length < 3) {
                        System.err.println("Error: Missing chain file or trust store argument");
                        printUsage();
                        System.exit(1);
                    }
                    String password = args.length > 3 ? args[3] : "";
                    result = verifier.validateWithCustomTrust(new File(args[1]), 
                            new File(args[2]), password);
                    break;

                case "validate-with-pem":
                    if (args.length < 3) {
                        System.err.println("Error: Missing chain file or trust anchor argument");
                        printUsage();
                        System.exit(1);
                    }
                    List<File> trustAnchors = new ArrayList<>();
                    for (int i = 2; i < args.length; i++) {
                        trustAnchors.add(new File(args[i]));
                    }
                    result = verifier.validateWithPemTrust(new File(args[1]), trustAnchors);
                    break;

                case "info":
                    if (args.length < 2) {
                        System.err.println("Error: Missing certificate file argument");
                        printUsage();
                        System.exit(1);
                    }
                    List<X509Certificate> certs = verifier.certificateLoader
                            .loadCertificateChain(new File(args[1]));
                    for (X509Certificate cert : certs) {
                        System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
                        System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
                        System.out.println("Serial: " + cert.getSerialNumber().toString(16).toUpperCase());
                        System.out.println("Valid From: " + cert.getNotBefore());
                        System.out.println("Valid To: " + cert.getNotAfter());
                        System.out.println("Signature Algorithm: " + cert.getSigAlgName());
                        System.out.println("Key Usage: " + java.util.Arrays.toString(cert.getKeyUsage()));
                        System.out.println("Basic Constraints: " + cert.getBasicConstraints());
                    }
                    System.exit(0);
                    return;

                case "extract":
                    if (args.length < 2) {
                        System.err.println("Error: Missing chain file argument");
                        printUsage();
                        System.exit(1);
                    }
                    List<X509Certificate> extractCerts = verifier.certificateLoader
                            .loadCertificateChain(new File(args[1]));
                    for (int i = 0; i < extractCerts.size(); i++) {
                        X509Certificate cert = extractCerts.get(i);
                        String filename = "cert_" + i + "_" + 
                                cert.getSerialNumber().toString(16) + ".der";
                        java.nio.file.Files.write(java.nio.file.Paths.get(filename), 
                                cert.getEncoded());
                        System.out.println("Extracted: " + filename);
                    }
                    System.exit(0);
                    return;

                default:
                    System.err.println("Error: Unknown command '" + command + "'");
                    printUsage();
                    System.exit(1);
                    return;
            }

            System.out.println("\nValidation Result:");
            System.out.println("==================");
            System.out.println("Status: " + (result.isValid() ? "VALID" : "INVALID"));
            if (!result.isValid()) {
                System.out.println("Error: " + result.getErrorMessage());
            } else {
                System.out.println("Message: " + result.getSuccessMessage());
            }
            
            System.exit(result.isValid() ? 0 : 1);

        } catch (CertificateException e) {
            System.err.println("Error initializing certificate verifier: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Represents the result of a certificate chain validation.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final String successMessage;

        private ValidationResult(boolean valid, String errorMessage, String successMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.successMessage = successMessage;
        }

        public static ValidationResult success(String message) {
            return new ValidationResult(true, null, message);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, error, null);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public String getSuccessMessage() {
            return successMessage;
        }
    }
}
