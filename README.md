# CWE-316: Canton Signing Key Password Persists in JVM Heap

**Target:** Swiss Post Data Integration Service (DIS) v2.9.3.0  
**Vulnerability:** Cleartext storage of sensitive cryptographic material in memory  
**CWE:** [CWE-316](https://cwe.mitre.org/data/definitions/316.html)  
**CVSS:** 7.6 High (CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)

## What This Proves

The DIS uses a canton-issued PKCS#12 keystore to sign every `configuration.xml` it produces. The keystore password is loaded from disk into a `char[]` array, used to extract the private signing key, and then **never zeroed from memory**.

This CI pipeline:

1. **Sets up JDK 21** — matching the DIS deployment target (`OpenJDK21U-jre_x64_windows_hotspot_21.0.9_10`)
2. **Creates a real PKCS#12 keystore** with an RSA signing key (replicating the canton keystore)
3. **Executes the exact DIS code flow** from `Tools.saveXML()`:
   - `KeystoreRepository.getCantonKeystorePassword()` → reads password from file
   - `KeyStore.load(stream, keystorePassword)` → opens the keystore
   - `KeyStore.getKey(alias, keystorePassword)` → extracts the private key
   - `XMLSignatureService.genXMLSignature()` → signs the configuration
   - **No cleanup** — function returns without `Arrays.fill()`
4. **Takes a programmatic heap dump** (equivalent to `jmap -dump`)
5. **Scans the heap dump** for the password bytes (UTF-8 and UTF-16)
6. **Reports VULNERABLE** when the password is found

## Affected Source Code

```
data-integration-service/
├── src/main/java/ch/post/it/evoting/dataintegrationservice/
│   ├── pipes/Tools.java                    ← Lines 86-99: password never zeroed
│   └── keystore/KeystoreRepository.java    ← Lines 47-49: byte[] intermediaries never zeroed
```

## Running Locally

```bash
cd src
javac --add-exports java.management/com.sun.management=ALL-UNNAMED DISPasswordLeakPoC.java
java  --add-exports java.management/com.sun.management=ALL-UNNAMED \
      --add-opens java.management/com.sun.management=ALL-UNNAMED \
      -Xmx256m DISPasswordLeakPoC
```

## Fix

```java
// In Tools.java, wrap the signing block:
try {
    final KeyStore keyStore = getKeyStore(keyStoreStream, keystorePassword);
    final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keystoreAlias.get(), keystorePassword);
    getBean(XMLSignatureService.class).genXMLSignature(is, fos, privateKey);
} finally {
    Arrays.fill(keystorePassword, '\0');
    keyStoreStream.close();
}
```
