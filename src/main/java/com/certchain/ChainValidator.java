package com.certchain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Chain Validator
 *
 * Performs X.509 certificate chain validation using the PKIX algorithm.
 * Supports revocation checking and custom validation parameters.
 */
public class ChainValidator {

    private static final Logger logger = LoggerFactory.getLogger(ChainValidator.class);

    private static final String PKIX_ALGORITHM = "PKIX";

    /**
     * Validates a certificate chain against a set of trust anchors.
     *
     * @param certificates the certificate chain to validate (end-entity first)
     * @param trustAnchors the set of trusted root certificates
     * @param certPathValidator the certificate path validator
     * @param certificateFactory the certificate factory
     * @param checkRevocation whether to check certificate revocation
     * @return ValidationResult containing the validation status and details
     */
    public CertChainVerifier.ValidationResult validate(List<X509Certificate> certificates,
                                                        Set<TrustAnchor> trustAnchors,
                                                        CertPathValidator certPathValidator,
                                                        CertificateFactory certificateFactory,
                                                        boolean checkRevocation) {
        if (certificates == null) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is null");
        }
        if (certificates.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is empty");
        }

        if (trustAnchors == null) {
            return CertChainVerifier.ValidationResult.failure(
                    "Trust anchors cannot be null");
        }
        if (trustAnchors.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "No trust anchors provided");
        }

        if (certPathValidator == null) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate path validator cannot be null");
        }

        if (certificateFactory == null) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate factory cannot be null");
        }

        try {
            validateCertificateDates(certificates);

            validateChainOrder(certificates);

            CertPath certPath = certificateFactory.generateCertPath(certificates);

            PKIXParameters params = createPKIXParameters(trustAnchors, checkRevocation);

            CertPathValidatorResult result = certPathValidator.validate(certPath, params);

            if (result instanceof PKIXCertPathValidatorResult) {
                PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;
                TrustAnchor trustedAnchor = pkixResult.getTrustAnchor();
                String anchorSubject = trustedAnchor.getTrustedCert() != null
                        ? trustedAnchor.getTrustedCert().getSubjectX500Principal().getName()
                        : trustedAnchor.getCA().toString();

                logger.debug("Certificate chain validated successfully. Trusted anchor: {}", anchorSubject);
                return CertChainVerifier.ValidationResult.success(
                        "Certificate chain is valid. Trusted anchor: " + anchorSubject);
            }

            logger.debug("Certificate chain validated successfully");
            return CertChainVerifier.ValidationResult.success(
                    "Certificate chain is valid");

        } catch (CertPathValidatorException e) {
            logger.error("Certificate validation failed: {}", e.getReason());
            return handleValidationException(e, certificates);
        } catch (InvalidAlgorithmParameterException e) {
            logger.error("Invalid algorithm parameters: {}", e.getMessage());
            return CertChainVerifier.ValidationResult.failure(
                    "Invalid algorithm parameters: " + e.getMessage());
        } catch (CertificateException e) {
            logger.error("Certificate parsing error: {}", e.getMessage());
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate parsing error: " + e.getMessage());
        }
    }

    /**
     * Validates that all certificates in the chain are within their validity period.
     *
     * @param certificates the certificates to check
     * @throws CertificateException if any certificate is expired or not yet valid
     */
    private void validateCertificateDates(List<X509Certificate> certificates)
            throws CertificateException {
        if (certificates == null) {
            throw new CertificateException("Certificate list cannot be null");
        }

        Date now = new Date();

        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            if (cert == null) {
                throw new CertificateException("Certificate at index " + i + " is null");
            }
            Date notBefore = cert.getNotBefore();
            Date notAfter = cert.getNotAfter();

            if (notBefore == null) {
                throw new CertificateException("Certificate " + i + " has no validity start date");
            }
            if (notAfter == null) {
                throw new CertificateException("Certificate " + i + " has no validity end date");
            }

            if (now.before(notBefore)) {
                long daysUntilValid = (notBefore.getTime() - now.getTime()) / (1000L * 60 * 60 * 24);
                String certType = getCertificateType(i, certificates.size());
                throw new CertificateException(String.format(
                        "Certificate is not yet valid.%n" +
                        "  Index:          %d (%s)%n" +
                        "  Subject:        %s%n" +
                        "  Issuer:         %s%n" +
                        "  Serial:         %s%n" +
                        "  Valid From:     %s%n" +
                        "  Valid To:       %s%n" +
                        "  Days Until Valid: %d day(s)",
                        i, certType,
                        cert.getSubjectX500Principal().getName(),
                        cert.getIssuerX500Principal().getName(),
                        cert.getSerialNumber().toString(16).toUpperCase(),
                        notBefore, notAfter,
                        daysUntilValid));
            }

            if (now.after(notAfter)) {
                long daysExpired = (now.getTime() - notAfter.getTime()) / (1000L * 60 * 60 * 24);
                String certType = getCertificateType(i, certificates.size());
                throw new CertificateException(String.format(
                        "Certificate has expired.%n" +
                        "  Index:          %d (%s)%n" +
                        "  Subject:        %s%n" +
                        "  Issuer:         %s%n" +
                        "  Serial:         %s%n" +
                        "  Valid From:     %s%n" +
                        "  Expired On:     %s%n" +
                        "  Days Expired:   %d day(s)",
                        i, certType,
                        cert.getSubjectX500Principal().getName(),
                        cert.getIssuerX500Principal().getName(),
                        cert.getSerialNumber().toString(16).toUpperCase(),
                        notBefore, notAfter,
                        daysExpired));
            }
        }
    }

    /**
     * Determines the type of certificate based on its position in the chain.
     *
     * @param index the position in the chain
     * @param totalSize the total number of certificates in the chain
     * @return a string describing the certificate type
     */
    private String getCertificateType(int index, int totalSize) {
        if (totalSize == 1) {
            return "End Entity";
        } else if (index == 0) {
            return "End Entity";
        } else if (index == totalSize - 1) {
            return "Root CA";
        } else {
            return "Intermediate CA";
        }
    }

    /**
     * Validates the order of certificates in the chain.
     * The chain should be ordered from end-entity to root.
     *
     * @param certificates the certificate chain
     * @throws CertificateException if the chain order is invalid
     */
    private void validateChainOrder(List<X509Certificate> certificates)
            throws CertificateException {
        if (certificates == null) {
            throw new CertificateException("Certificate list cannot be null");
        }

        for (int i = 0; i < certificates.size() - 1; i++) {
            X509Certificate current = certificates.get(i);
            X509Certificate next = certificates.get(i + 1);

            if (current == null) {
                throw new CertificateException("Certificate at index " + i + " is null");
            }
            if (next == null) {
                throw new CertificateException("Certificate at index " + (i + 1) + " is null");
            }

            if (!current.getIssuerX500Principal().equals(
                    next.getSubjectX500Principal())) {
                throw new CertificateException(String.format(
                        "Chain order error: Certificate %d issuer does not match " +
                        "Certificate %d subject", i, i + 1));
            }
        }
    }

    /**
     * Creates PKIX parameters for certificate path validation.
     *
     * @param trustAnchors the set of trust anchors
     * @param checkRevocation whether to enable revocation checking
     * @return configured PKIX parameters
     * @throws InvalidAlgorithmParameterException if parameters are invalid
     */
    private PKIXParameters createPKIXParameters(Set<TrustAnchor> trustAnchors,
                                               boolean checkRevocation)
            throws InvalidAlgorithmParameterException {
        if (trustAnchors == null) {
            throw new InvalidAlgorithmParameterException("Trust anchors cannot be null");
        }

        PKIXParameters params = new PKIXParameters(trustAnchors);

        params.setRevocationEnabled(checkRevocation);

        if (checkRevocation) {
            try {
                PKIXRevocationChecker revocationChecker =
                        (PKIXRevocationChecker) CertPathValidator.getInstance(PKIX_ALGORITHM)
                                .getRevocationChecker();
                revocationChecker.setOptions(Collections.singleton(
                        PKIXRevocationChecker.Option.NO_FALLBACK));
                params.addCertPathChecker(revocationChecker);
                logger.debug("Revocation checking enabled");
            } catch (Exception e) {
                logger.warn("Could not configure revocation checker: {}", e.getMessage());
            }
        }

        params.setExplicitPolicyRequired(false);

        return params;
    }

    /**
     * Handles certificate path validation exceptions and provides detailed error messages.
     *
     * @param e the validation exception
     * @param certificates the certificate chain being validated
     * @return a ValidationResult with detailed error information
     */
    private CertChainVerifier.ValidationResult handleValidationException(
            CertPathValidatorException e, List<X509Certificate> certificates) {

        String reason = e.getReason() != null ? e.getReason().toString() : "Unknown reason";
        int index = e.getIndex();

        StringBuilder errorMessage = new StringBuilder();

        if (reason.toLowerCase().contains("expired")) {
            errorMessage.append("Certificate chain validation failed: Certificate has expired");
        } else if (reason.toLowerCase().contains("not yet valid")) {
            errorMessage.append("Certificate chain validation failed: Certificate is not yet valid");
        } else {
            errorMessage.append("Certificate chain validation failed: ").append(reason);
        }

        if (index >= 0 && certificates != null && index < certificates.size()) {
            X509Certificate failedCert = certificates.get(index);
            if (failedCert != null) {
                errorMessage.append("\nFailed at certificate index: ").append(index);
                errorMessage.append("\nSubject: ").append(
                        failedCert.getSubjectX500Principal().getName());
                errorMessage.append("\nIssuer: ").append(
                        failedCert.getIssuerX500Principal().getName());
                errorMessage.append("\nSerial: ").append(
                        failedCert.getSerialNumber().toString(16).toUpperCase());
                errorMessage.append("\nValid From: ").append(failedCert.getNotBefore());
                errorMessage.append("\nValid To: ").append(failedCert.getNotAfter());

                Date now = new Date();
                Date notAfter = failedCert.getNotAfter();
                Date notBefore = failedCert.getNotBefore();

                if (notAfter != null && now.after(notAfter)) {
                    long daysExpired = (now.getTime() - notAfter.getTime()) / (1000L * 60 * 60 * 24);
                    errorMessage.append("\nDays Expired: ").append(daysExpired).append(" day(s)");
                }

                if (notBefore != null && now.before(notBefore)) {
                    long daysUntilValid = (notBefore.getTime() - now.getTime()) / (1000L * 60 * 60 * 24);
                    errorMessage.append("\nDays Until Valid: ").append(daysUntilValid).append(" day(s)");
                }
            }
        }

        Throwable cause = e.getCause();
        if (cause != null) {
            errorMessage.append("\nCause: ").append(cause.getMessage());
        }

        logger.debug("Validation exception details: {}", errorMessage);

        return CertChainVerifier.ValidationResult.failure(errorMessage.toString());
    }

    /**
     * Performs basic chain validation without PKIX validation.
     * Checks chain ordering and issuer/subject relationships.
     *
     * @param certificates the certificate chain to validate
     * @return ValidationResult with basic validation results
     */
    public CertChainVerifier.ValidationResult validateBasicChain(
            List<X509Certificate> certificates) {
        if (certificates == null) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is null");
        }
        if (certificates.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is empty");
        }

        try {
            validateCertificateDates(certificates);
            validateChainOrder(certificates);

            X509Certificate endEntity = certificates.get(0);
            X509Certificate root = certificates.get(certificates.size() - 1);

            StringBuilder message = new StringBuilder();
            message.append("Basic chain validation passed. ");
            message.append("Chain length: ").append(certificates.size());
            message.append(", End entity: ").append(
                    endEntity.getSubjectX500Principal().getName());
            message.append(", Root: ").append(
                    root.getSubjectX500Principal().getName());

            logger.debug("Basic chain validation passed: {}", message);
            return CertChainVerifier.ValidationResult.success(message.toString());

        } catch (CertificateException e) {
            logger.error("Basic chain validation failed: {}", e.getMessage());
            return CertChainVerifier.ValidationResult.failure(e.getMessage());
        }
    }

    /**
     * Checks if a certificate is self-signed.
     *
     * @param certificate the certificate to check
     * @return true if the certificate is self-signed
     */
    public boolean isSelfSigned(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }
        return certificate.getSubjectX500Principal().equals(
                certificate.getIssuerX500Principal());
    }

    /**
     * Finds the root certificate in a chain.
     *
     * @param certificates the certificate chain
     * @return the root certificate, or null if not found
     */
    public X509Certificate findRootCertificate(List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return null;
        }

        for (X509Certificate cert : certificates) {
            if (cert != null && isSelfSigned(cert)) {
                return cert;
            }
        }

        return certificates.get(certificates.size() - 1);
    }

    /**
     * Validates that a certificate chain forms a complete path to a root.
     *
     * @param certificates the certificate chain
     * @return true if the chain ends with a self-signed root certificate
     */
    public boolean isCompleteChain(List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return false;
        }

        X509Certificate lastCert = certificates.get(certificates.size() - 1);
        return lastCert != null && isSelfSigned(lastCert);
    }

    /**
     * Extracts the certificate path as a list of subject names.
     *
     * @param certificates the certificate chain
     * @return list of subject distinguished names
     */
    public List<String> getCertificatePathSubjects(List<X509Certificate> certificates) {
        List<String> subjects = new ArrayList<>();
        if (certificates == null) {
            return subjects;
        }
        for (X509Certificate cert : certificates) {
            if (cert != null) {
                subjects.add(cert.getSubjectX500Principal().getName());
            }
        }
        return subjects;
    }
}
