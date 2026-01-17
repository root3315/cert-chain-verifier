package com.certchain;

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
        if (certificates == null || certificates.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is empty or null");
        }

        if (trustAnchors == null || trustAnchors.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "No trust anchors provided");
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
                
                return CertChainVerifier.ValidationResult.success(
                        "Certificate chain is valid. Trusted anchor: " + anchorSubject);
            }

            return CertChainVerifier.ValidationResult.success(
                    "Certificate chain is valid");

        } catch (CertPathValidatorException e) {
            return handleValidationException(e, certificates);
        } catch (InvalidAlgorithmParameterException e) {
            return CertChainVerifier.ValidationResult.failure(
                    "Invalid algorithm parameters: " + e.getMessage());
        } catch (CertificateException e) {
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
        Date now = new Date();
        
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            Date notBefore = cert.getNotBefore();
            Date notAfter = cert.getNotAfter();
            
            if (now.before(notBefore)) {
                throw new CertificateException(String.format(
                        "Certificate %d is not yet valid. Valid from: %s", i, notBefore));
            }
            
            if (now.after(notAfter)) {
                throw new CertificateException(String.format(
                        "Certificate %d has expired. Expired on: %s", i, notAfter));
            }
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
        for (int i = 0; i < certificates.size() - 1; i++) {
            X509Certificate current = certificates.get(i);
            X509Certificate next = certificates.get(i + 1);
            
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
            } catch (Exception e) {
                System.out.println("Warning: Could not configure revocation checker: " + e.getMessage());
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
        
        String reason = e.getReason();
        int index = e.getIndex();
        
        StringBuilder errorMessage = new StringBuilder();
        errorMessage.append("Certificate validation failed: ").append(reason);
        
        if (index >= 0 && index < certificates.size()) {
            X509Certificate failedCert = certificates.get(index);
            errorMessage.append("\nFailed at certificate index: ").append(index);
            errorMessage.append("\nSubject: ").append(
                    failedCert.getSubjectX500Principal().getName());
            errorMessage.append("\nIssuer: ").append(
                    failedCert.getIssuerX500Principal().getName());
            errorMessage.append("\nSerial: ").append(
                    failedCert.getSerialNumber().toString(16).toUpperCase());
        }
        
        Throwable cause = e.getCause();
        if (cause != null) {
            errorMessage.append("\nCause: ").append(cause.getMessage());
        }
        
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
        if (certificates == null || certificates.isEmpty()) {
            return CertChainVerifier.ValidationResult.failure(
                    "Certificate chain is empty or null");
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
            
            return CertChainVerifier.ValidationResult.success(message.toString());
            
        } catch (CertificateException e) {
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
            if (isSelfSigned(cert)) {
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
        return isSelfSigned(lastCert);
    }

    /**
     * Extracts the certificate path as a list of subject names.
     *
     * @param certificates the certificate chain
     * @return list of subject distinguished names
     */
    public List<String> getCertificatePathSubjects(List<X509Certificate> certificates) {
        List<String> subjects = new ArrayList<>();
        for (X509Certificate cert : certificates) {
            subjects.add(cert.getSubjectX500Principal().getName());
        }
        return subjects;
    }
}
