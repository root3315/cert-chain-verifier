# Certificate Chain Verifier

A Java command-line tool for validating X.509 certificate chains with customizable trust anchors.

## Description

This tool provides comprehensive X.509 certificate chain validation capabilities:

- **Chain Validation**: Validates certificate chains against trusted root CAs
- **Multiple Trust Sources**: Supports system trust store, custom JKS/PKCS12 stores, and PEM files
- **Format Support**: Handles both PEM (Base64) and DER (binary) certificate formats
- **Detailed Output**: Provides detailed certificate information and validation results
- **Revocation Checking**: Optional certificate revocation status verification

## Requirements

- Java 11 or higher
- Maven 3.6 or higher (for building)

## Installation

### Build from Source

```bash
# Clone or navigate to the project directory
cd cert-chain-verifier

# Build the project
mvn clean package

# The executable JAR will be in target/
ls target/*.jar
```

### Build with Dependencies

To create a fat JAR with all dependencies included:

```bash
mvn clean package assembly:single
```

This creates `target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar`

## Usage

### Basic Commands

```bash
# Show help
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar --help

# Show version
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar --version
```

### Validate Certificate Chain

**Using System Trust Store:**

```bash
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar validate server-chain.pem
```

**Using Custom Trust Store (JKS/PKCS12):**

```bash
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar validate-with-store chain.pem truststore.jks [password]
```

**Using PEM Trust Anchors:**

```bash
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar validate-with-pem chain.pem root-ca.pem intermediate-ca.pem
```

### Certificate Information

```bash
# Display certificate details
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar info certificate.pem
```

### Extract Certificates

```bash
# Extract individual certificates from a chain
java -jar target/cert-chain-verifier-1.0.0-jar-with-dependencies.jar extract chain.pem
```

## How It Works

### Certificate Chain Validation

The validator uses the Java PKIX (Public Key Infrastructure using X.509) algorithm to validate certificate chains:

1. **Load Certificates**: Parses the input file (PEM or DER format) to extract certificates
2. **Order Verification**: Ensures certificates are properly ordered (end-entity to root)
3. **Date Validation**: Checks that all certificates are within their validity period
4. **Signature Verification**: Validates each certificate's signature against its issuer
5. **Trust Anchor Matching**: Verifies the chain terminates at a trusted root CA
6. **Path Building**: Constructs and validates the certification path

### Trust Anchor Sources

The tool supports multiple trust anchor sources:

- **System Trust Store**: Uses the JVM's default `cacerts` file
- **Custom KeyStore**: Loads from JKS or PKCS12 format files
- **PEM Files**: Directly loads trusted certificates from PEM files

### Supported Formats

**PEM Format:**
```
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
...
-----END CERTIFICATE-----
```

**DER Format:** Binary ASN.1 encoded certificate

## Project Structure

```
cert-chain-verifier/
├── pom.xml                          # Maven build configuration
├── README.md                        # This documentation
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── certchain/
│   │               ├── CertChainVerifier.java    # Main entry point
│   │               ├── CertificateLoader.java    # Certificate parsing
│   │               ├── ChainValidator.java       # Validation logic
│   │               └── TrustStoreManager.java    # Trust store handling
│   └── test/
│       └── java/
│           └── com/
│               └── certchain/
│                   └── CertChainVerifierTest.java # Unit tests
```

## Core Classes

### CertChainVerifier

Main entry point providing:
- Command-line interface
- Chain validation orchestration
- Certificate information display

### CertificateLoader

Handles certificate loading and format conversion:
- PEM/DER format detection
- Multi-certificate chain parsing
- PEM encoding/decoding

### ChainValidator

Implements validation logic:
- PKIX path validation
- Date validity checking
- Chain order verification
- Self-signed certificate detection

### TrustStoreManager

Manages trust anchor sources:
- System trust store loading
- Custom KeyStore handling
- Trust anchor extraction

## Running Tests

```bash
# Run all tests
mvn test

# Run with coverage
mvn clean test jacoco:report
```

## Examples

### Validating a Server Certificate

```bash
# Download a certificate chain
openssl s_client -connect www.example.com:443 -showcerts > example-chain.pem

# Validate against system trust
java -jar cert-chain-verifier.jar validate example-chain.pem
```

### Creating a Custom Trust Store

```bash
# Create a new trust store
keytool -genkey -alias myca -keyalg RSA -keystore mytrust.jks

# Add a CA certificate
keytool -import -alias rootca -file root-ca.pem -keystore mytrust.jks

# Validate using custom trust
java -jar cert-chain-verifier.jar validate-with-store chain.pem mytrust.jks password
```

### Programmatic Usage

```java
import com.certchain.CertChainVerifier;
import com.certchain.CertChainVerifier.ValidationResult;
import java.io.File;

public class Example {
    public static void main(String[] args) throws Exception {
        CertChainVerifier verifier = new CertChainVerifier();
        
        // Validate with system trust
        ValidationResult result = verifier.validateWithSystemTrust(
            new File("server-chain.pem")
        );
        
        if (result.isValid()) {
            System.out.println("Chain is valid!");
        } else {
            System.out.println("Validation failed: " + result.getErrorMessage());
        }
    }
}
```

## Exit Codes

- `0`: Validation successful
- `1`: Validation failed or error occurred

## Troubleshooting

### Common Errors

**"No certificates found in the chain file"**
- Ensure the file contains valid PEM or DER encoded certificates
- Check file encoding (should be UTF-8 for PEM)

**"Certificate has expired"**
- Check the certificate validity dates using the `info` command
- Obtain a renewed certificate from the issuer

**"No trust anchors provided"**
- Ensure the trust store file exists and is accessible
- Verify the trust store password is correct

**"Chain order error"**
- Certificates should be ordered from end-entity to root
- Reorder the certificates in the chain file

## License

This project is provided as-is for educational and testing purposes.
