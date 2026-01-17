package com.certchain;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Certificate Loader
 * 
 * Utility class for loading X.509 certificates from various file formats
 * including PEM (Base64-encoded) and DER (binary) formats.
 */
public class CertificateLoader {

    private static final String PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_CERT_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(
            PEM_CERT_HEADER + "(.*?)" + PEM_CERT_FOOTER, Pattern.DOTALL);

    private final CertificateFactory certificateFactory;

    public CertificateLoader(CertificateFactory certificateFactory) {
        this.certificateFactory = certificateFactory;
    }

    /**
     * Loads a certificate chain from a file.
     * Automatically detects whether the file is PEM or DER format.
     *
     * @param file the certificate file to load
     * @return list of X.509 certificates in the chain
     * @throws CertificateException if the file cannot be parsed
     * @throws IOException if the file cannot be read
     */
    public List<X509Certificate> loadCertificateChain(File file) 
            throws CertificateException, IOException {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        
        if (content.contains(PEM_CERT_HEADER)) {
            return loadPemCertificateChain(content);
        } else {
            return loadDerCertificateChain(file);
        }
    }

    /**
     * Loads a single certificate from a file.
     *
     * @param file the certificate file to load
     * @return the X.509 certificate
     * @throws CertificateException if the file cannot be parsed
     * @throws IOException if the file cannot be read
     */
    public X509Certificate loadSingleCertificate(File file) 
            throws CertificateException, IOException {
        List<X509Certificate> certificates = loadCertificateChain(file);
        if (certificates.isEmpty()) {
            throw new CertificateException("No certificate found in file: " + file.getName());
        }
        return certificates.get(0);
    }

    /**
     * Loads certificates from PEM-encoded content.
     *
     * @param pemContent the PEM-encoded certificate content
     * @return list of X.509 certificates
     * @throws CertificateException if the content cannot be parsed
     */
    public List<X509Certificate> loadPemCertificateChain(String pemContent) 
            throws CertificateException {
        List<X509Certificate> certificates = new ArrayList<>();
        Matcher matcher = PEM_PATTERN.matcher(pemContent);
        
        while (matcher.find()) {
            String base64Cert = matcher.group(1)
                    .replaceAll("\\s+", "")
                    .replaceAll("[\\r\\n]", "");
            
            if (!base64Cert.isEmpty()) {
                try {
                    byte[] certBytes = Base64.getDecoder().decode(base64Cert);
                    X509Certificate cert = (X509Certificate) certificateFactory
                            .generateCertificate(new ByteArrayInputStream(certBytes));
                    certificates.add(cert);
                } catch (IllegalArgumentException e) {
                    throw new CertificateException("Invalid Base64 encoding in certificate: " + e.getMessage());
                }
            }
        }
        
        return certificates;
    }

    /**
     * Loads certificates from a DER-encoded file.
     * For chain files, expects concatenated DER certificates.
     *
     * @param file the DER-encoded certificate file
     * @return list of X.509 certificates
     * @throws CertificateException if the file cannot be parsed
     * @throws IOException if the file cannot be read
     */
    public List<X509Certificate> loadDerCertificateChain(File file) 
            throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] fileBytes = fis.readAllBytes();
            
            int offset = 0;
            while (offset < fileBytes.length) {
                try {
                    X509Certificate cert = (X509Certificate) certificateFactory
                            .generateCertificate(new ByteArrayInputStream(
                                    fileBytes, offset, fileBytes.length - offset));
                    certificates.add(cert);
                    
                    offset += cert.getEncoded().length;
                } catch (CertificateException e) {
                    if (certificates.isEmpty()) {
                        throw e;
                    }
                    break;
                }
            }
        }
        
        return certificates;
    }

    /**
     * Loads a certificate from a byte array.
     *
     * @param certBytes the certificate bytes
     * @return the X.509 certificate
     * @throws CertificateException if the bytes cannot be parsed
     */
    public X509Certificate loadCertificateFromBytes(byte[] certBytes) 
            throws CertificateException {
        return (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /**
     * Extracts the raw certificate bytes from PEM-encoded content.
     *
     * @param pemContent the PEM-encoded certificate content
     * @return list of raw certificate byte arrays
     * @throws CertificateException if the content cannot be parsed
     */
    public List<byte[]> extractCertificateBytes(String pemContent) 
            throws CertificateException {
        List<byte[]> certBytesList = new ArrayList<>();
        Matcher matcher = PEM_PATTERN.matcher(pemContent);
        
        while (matcher.find()) {
            String base64Cert = matcher.group(1)
                    .replaceAll("\\s+", "")
                    .replaceAll("[\\r\\n]", "");
            
            if (!base64Cert.isEmpty()) {
                try {
                    byte[] certBytes = Base64.getDecoder().decode(base64Cert);
                    certBytesList.add(certBytes);
                } catch (IllegalArgumentException e) {
                    throw new CertificateException("Invalid Base64 encoding: " + e.getMessage());
                }
            }
        }
        
        return certBytesList;
    }

    /**
     * Converts a certificate to PEM format.
     *
     * @param certificate the certificate to convert
     * @return PEM-encoded certificate string
     * @throws CertificateException if encoding fails
     */
    public String toPemFormat(X509Certificate certificate) throws CertificateException {
        String base64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append(PEM_CERT_HEADER).append("\n");
        
        int lineLength = 64;
        for (int i = 0; i < base64.length(); i += lineLength) {
            int end = Math.min(i + lineLength, base64.length());
            pem.append(base64, i, end).append("\n");
        }
        
        pem.append(PEM_CERT_FOOTER).append("\n");
        return pem.toString();
    }

    /**
     * Converts a list of certificates to PEM format (chain).
     *
     * @param certificates the certificates to convert
     * @return PEM-encoded certificate chain string
     * @throws CertificateException if encoding fails
     */
    public String toPemFormat(List<X509Certificate> certificates) throws CertificateException {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate cert : certificates) {
            pem.append(toPemFormat(cert));
        }
        return pem.toString();
    }

    /**
     * Checks if a file contains PEM-encoded certificates.
     *
     * @param file the file to check
     * @return true if the file contains PEM-encoded certificates
     * @throws IOException if the file cannot be read
     */
    public static boolean isPemFile(File file) throws IOException {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        return content.contains(PEM_CERT_HEADER) && content.contains(PEM_CERT_FOOTER);
    }

    /**
     * Validates the format of a PEM certificate string.
     *
     * @param pemContent the PEM content to validate
     * @return true if the format is valid
     */
    public static boolean isValidPemFormat(String pemContent) {
        if (!pemContent.contains(PEM_CERT_HEADER) || 
            !pemContent.contains(PEM_CERT_FOOTER)) {
            return false;
        }
        
        Matcher matcher = PEM_PATTERN.matcher(pemContent);
        while (matcher.find()) {
            String base64Cert = matcher.group(1).replaceAll("\\s+", "");
            if (base64Cert.isEmpty()) {
                return false;
            }
            try {
                Base64.getDecoder().decode(base64Cert);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return true;
    }
}
