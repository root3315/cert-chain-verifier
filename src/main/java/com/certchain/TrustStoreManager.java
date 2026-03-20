package com.certchain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Trust Store Manager
 *
 * Manages loading and handling of trust stores containing trusted
 * certificate authorities. Supports JKS, PKCS12, and system default trust stores.
 */
public class TrustStoreManager {

    private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
    private static final String PKCS12_TYPE = "PKCS12";
    private static final String SYSTEM_TRUST_STORE_TYPE = "JKS";

    /**
     * Loads trust anchors from the system default trust store.
     *
     * @return set of trust anchors from the system trust store
     * @throws KeyStoreException if the trust store cannot be accessed
     * @throws IOException if the trust store cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws CertificateException if certificates cannot be loaded
     */
    public Set<TrustAnchor> loadSystemTrustAnchors()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        String trustStorePath = System.getProperty("java.home");
        if (trustStorePath == null) {
            throw new KeyStoreException("Cannot determine Java home directory");
        }

        String cacertsPath = trustStorePath +
                File.separator + "lib" +
                File.separator + "security" +
                File.separator + "cacerts";

        File cacertsFile = new File(cacertsPath);
        if (!cacertsFile.exists()) {
            cacertsPath = trustStorePath +
                    File.separator + "jre" +
                    File.separator + "lib" +
                    File.separator + "security" +
                    File.separator + "cacerts";
            cacertsFile = new File(cacertsPath);
        }

        if (!cacertsFile.exists()) {
            throw new KeyStoreException("System trust store not found at: " + cacertsPath);
        }

        return loadTrustAnchorsFromFile(cacertsFile, "changeit");
    }

    /**
     * Loads trust anchors from a custom trust store file.
     *
     * @param trustStoreFile the trust store file
     * @param password the trust store password
     * @return set of trust anchors
     * @throws KeyStoreException if the trust store cannot be accessed
     * @throws IOException if the trust store cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws CertificateException if certificates cannot be loaded
     */
    public Set<TrustAnchor> loadTrustAnchorsFromFile(File trustStoreFile, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        if (trustStoreFile == null) {
            throw new IllegalArgumentException("Trust store file cannot be null");
        }
        if (!trustStoreFile.exists()) {
            throw new IOException("Trust store file does not exist: " + trustStoreFile.getPath());
        }

        String type = detectKeyStoreType(trustStoreFile);
        KeyStore trustStore = KeyStore.getInstance(type);

        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            char[] passwordChars = password != null ? password.toCharArray() : new char[0];
            trustStore.load(fis, passwordChars);
        }

        return extractTrustAnchors(trustStore);
    }

    /**
     * Loads trust anchors from a KeyStore object.
     *
     * @param keyStore the KeyStore containing trusted certificates
     * @return set of trust anchors
     * @throws KeyStoreException if the trust store cannot be accessed
     */
    public Set<TrustAnchor> loadTrustAnchorsFromKeyStore(KeyStore keyStore)
            throws KeyStoreException {
        if (keyStore == null) {
            throw new IllegalArgumentException("KeyStore cannot be null");
        }
        return extractTrustAnchors(keyStore);
    }

    /**
     * Creates a new empty KeyStore for adding trust anchors.
     *
     * @param type the KeyStore type (JKS or PKCS12)
     * @return a new empty KeyStore
     * @throws KeyStoreException if the KeyStore cannot be created
     */
    public KeyStore createEmptyKeyStore(String type) throws KeyStoreException {
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("KeyStore type cannot be null or empty");
        }
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        return keyStore;
    }

    /**
     * Adds a certificate as a trust anchor to a KeyStore.
     *
     * @param keyStore the KeyStore to add to
     * @param alias the alias for the certificate
     * @param certificate the certificate to add
     * @throws KeyStoreException if the certificate cannot be added
     */
    public void addTrustAnchor(KeyStore keyStore, String alias, X509Certificate certificate)
            throws KeyStoreException {
        if (keyStore == null) {
            throw new IllegalArgumentException("KeyStore cannot be null");
        }
        if (alias == null || alias.isEmpty()) {
            throw new IllegalArgumentException("Alias cannot be null or empty");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        keyStore.setCertificateEntry(alias, certificate);
    }

    /**
     * Saves a KeyStore to a file.
     *
     * @param keyStore the KeyStore to save
     * @param file the file to save to
     * @param password the password for the KeyStore
     * @throws IOException if the file cannot be written
     * @throws KeyStoreException if the KeyStore cannot be saved
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws CertificateException if certificates cannot be encoded
     */
    public void saveKeyStore(KeyStore keyStore, File file, String password)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        if (keyStore == null) {
            throw new IllegalArgumentException("KeyStore cannot be null");
        }
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }

        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
            char[] passwordChars = password != null ? password.toCharArray() : new char[0];
            keyStore.store(fos, passwordChars);
        }
    }

    /**
     * Detects the KeyStore type based on file extension and content.
     *
     * @param file the KeyStore file
     * @return the detected KeyStore type
     */
    private String detectKeyStoreType(File file) {
        if (file == null) {
            return DEFAULT_KEYSTORE_TYPE;
        }

        String fileName = file.getName().toLowerCase();

        if (fileName.endsWith(".p12") || fileName.endsWith(".pkcs12")) {
            return PKCS12_TYPE;
        }

        if (fileName.endsWith(".jks")) {
            return DEFAULT_KEYSTORE_TYPE;
        }

        return DEFAULT_KEYSTORE_TYPE;
    }

    /**
     * Extracts trust anchors from a KeyStore.
     *
     * @param keyStore the KeyStore to extract from
     * @return set of trust anchors
     * @throws KeyStoreException if the KeyStore cannot be accessed
     */
    private Set<TrustAnchor> extractTrustAnchors(KeyStore keyStore)
            throws KeyStoreException {
        if (keyStore == null) {
            throw new KeyStoreException("KeyStore cannot be null");
        }

        Set<TrustAnchor> trustAnchors = new HashSet<>();

        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keyStore.isCertificateEntry(alias)) {
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    trustAnchors.add(new TrustAnchor(x509Cert, null));
                }
            }
        }

        return trustAnchors;
    }

    /**
     * Gets the count of trusted certificates in a KeyStore.
     *
     * @param keyStore the KeyStore to count
     * @return the number of trusted certificate entries
     * @throws KeyStoreException if the KeyStore cannot be accessed
     */
    public int getTrustAnchorCount(KeyStore keyStore) throws KeyStoreException {
        if (keyStore == null) {
            throw new IllegalArgumentException("KeyStore cannot be null");
        }

        int count = 0;
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Checks if a certificate is present in the trust store.
     *
     * @param keyStore the KeyStore to check
     * @param certificate the certificate to look for
     * @return true if the certificate is in the trust store
     * @throws KeyStoreException if the KeyStore cannot be accessed
     */
    public boolean containsCertificate(KeyStore keyStore, X509Certificate certificate)
            throws KeyStoreException {
        if (keyStore == null) {
            throw new IllegalArgumentException("KeyStore cannot be null");
        }
        if (certificate == null) {
            return false;
        }

        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                Certificate cert = keyStore.getCertificate(alias);
                if (cert != null && cert.equals(certificate)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Gets the default system trust store path.
     *
     * @return the path to the system trust store, or null if not found
     */
    public String getSystemTrustStorePath() {
        String javaHome = System.getProperty("java.home");
        if (javaHome == null) {
            return null;
        }

        String cacertsPath = javaHome +
                File.separator + "lib" +
                File.separator + "security" +
                File.separator + "cacerts";

        if (new File(cacertsPath).exists()) {
            return cacertsPath;
        }

        String jreCacertsPath = javaHome +
                File.separator + "jre" +
                File.separator + "lib" +
                File.separator + "security" +
                File.separator + "cacerts";

        if (new File(jreCacertsPath).exists()) {
            return jreCacertsPath;
        }

        return null;
    }

    /**
     * Creates a trust anchor from a certificate file.
     *
     * @param certFile the certificate file
     * @param certificateLoader the certificate loader to use
     * @return the trust anchor
     * @throws CertificateException if the certificate cannot be loaded
     * @throws IOException if the file cannot be read
     */
    public TrustAnchor createTrustAnchorFromFile(File certFile, CertificateLoader certificateLoader)
            throws CertificateException, IOException {
        if (certFile == null) {
            throw new IllegalArgumentException("Certificate file cannot be null");
        }
        if (certificateLoader == null) {
            throw new IllegalArgumentException("CertificateLoader cannot be null");
        }
        if (!certFile.exists()) {
            throw new IOException("Certificate file does not exist: " + certFile.getPath());
        }

        X509Certificate cert = certificateLoader.loadSingleCertificate(certFile);
        return new TrustAnchor(cert, null);
    }

    /**
     * Merges trust anchors from multiple KeyStores.
     *
     * @param keyStores the KeyStores to merge
     * @return combined set of trust anchors
     * @throws KeyStoreException if any KeyStore cannot be accessed
     */
    public Set<TrustAnchor> mergeTrustAnchors(KeyStore... keyStores)
            throws KeyStoreException {
        if (keyStores == null) {
            throw new IllegalArgumentException("KeyStores array cannot be null");
        }

        Set<TrustAnchor> merged = new HashSet<>();

        for (KeyStore keyStore : keyStores) {
            if (keyStore != null) {
                merged.addAll(extractTrustAnchors(keyStore));
            }
        }

        return merged;
    }

    /**
     * Validates that a trust store is properly formatted and accessible.
     *
     * @param trustStoreFile the trust store file
     * @param password the trust store password
     * @return true if the trust store is valid
     */
    public boolean isValidTrustStore(File trustStoreFile, String password) {
        if (trustStoreFile == null) {
            return false;
        }
        if (!trustStoreFile.exists()) {
            return false;
        }

        try {
            KeyStore keyStore = KeyStore.getInstance(detectKeyStoreType(trustStoreFile));
            try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
                char[] passwordChars = password != null ? password.toCharArray() : new char[0];
                keyStore.load(fis, passwordChars);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
