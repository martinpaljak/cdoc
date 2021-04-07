/*
 * Copyright (C) 2017 Martin Paljak <martin@martinpaljak.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.cdoc4j.cli;

import apdu4j.HexUtils;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.PathConverter;
import joptsimple.util.PathProperties;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.cdoc4j.*;
import org.esteid.sk.IDCode;
import org.esteid.sk.LDAP;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CardNotPresentException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Tool {
    private static final String OPT_VERSION = "version";
    private static final String OPT_KEY = "key";
    private static final String OPT_CDOCV2 = "cdoc2";
    private static final String OPT_OUT = "out";
    private static final String OPT_LEGACY = "legacy";
    private static final String OPT_DEBUG = "debug";
    private static final String OPT_VERBOSE = "verbose";
    private static final String OPT_FORCE = "force";
    private static final String OPT_ISSUER = "issuer";
    private static final String OPT_RECIPIENT = "receiver";
    private static final String OPT_VALIDATE = "validate";
    private static final String OPT_PRIVACY = "privacy";
    private static final String OPT_LIST = "list";


    private static OptionSet args = null;

    public static void main(String[] argv) throws Exception {
        OptionParser parser = new OptionParser();

        // Generic options
        parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show version");
        parser.acceptsAll(Arrays.asList("?", "help"), "Show this help");
        parser.acceptsAll(Arrays.asList("D", OPT_DEBUG), "Enable low-level debugging");
        parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose");
        parser.acceptsAll(Arrays.asList("f", OPT_FORCE), "Force operations, omitting checks");
        parser.acceptsAll(Arrays.asList("k", OPT_KEY), "Use key to decrypt").withRequiredArg();
        parser.acceptsAll(Arrays.asList("o", OPT_OUT), "Save output to").withRequiredArg().withValuesConvertedBy(new PathConverter());
        parser.acceptsAll(Arrays.asList("i", OPT_ISSUER), "Allowed issuer certificate").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("p", OPT_PRIVACY), "Respect privacy");
        parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List recipients");
        parser.acceptsAll(Arrays.asList("2", OPT_CDOCV2), "Create a CDOC 2.0 file");
        parser.acceptsAll(Arrays.asList("X", OPT_VALIDATE), "Validate generated XML");
        parser.accepts(OPT_LEGACY, "Create a legacy CDOC 1.0 file");

        // Type safety
        OptionSpec<Path> recipient_pems = parser.acceptsAll(Arrays.asList("r", OPT_RECIPIENT), "Receiver cert").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        // The rest
        OptionSpec<String> others = parser.nonOptions("files and ID-codes");

        // Parse arguments
        try {
            args = parser.parse(argv);
            if (args.has("help")) {
                parser.printHelpOn(System.out);
                System.exit(0);
            }
        } catch (OptionException e) {
            if (e.getCause() != null) {
                System.err.println(e.getMessage() + ": " + e.getCause().getMessage());
            } else {
                System.err.println(e.getMessage());
            }
            System.err.println();
            parser.printHelpOn(System.err);
            System.exit(1);
        }

        try {
            // Test for unlimited crypto
            if (Cipher.getMaxAllowedKeyLength("AES") == 128) {
                System.err.println("WARNING: Unlimited crypto policy is NOT installed!");
                if (System.getProperty("java.vendor").contains("Oracle")) {
                    String jv = System.getProperty("java.version");
                    if (jv.startsWith("1.8")) {
                        String[] jvb = jv.split("_");
                        if (jvb.length == 2 && Integer.parseInt(jvb[1]) >= 151) {
                            String jh = System.getProperty("java.home");
                            System.err.println("Trying to fix automatically for " + jh + " ...");
                            Path sf = Paths.get(jh, "lib", "security", "java.security");
                            Path sftmp = Paths.get(jh, "lib", "security", "java.security.tmp");
                            Path sfbak = Paths.get(jh, "lib", "security", "java.security.bak");
                            try {
                                List<String> lines = Files.readAllLines(sf);
                                lines.add("crypto.policy=unlimited");
                                Files.write(sftmp, lines);
                                Files.copy(sf, sfbak, StandardCopyOption.REPLACE_EXISTING);
                                Files.move(sftmp, sf, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                            } catch (AccessDeniedException e) {
                                System.err.println("FAILED: Access denied.");
                                System.err.println("Please run cdoc with sudo to automatically fix the problem by modifying:");
                                System.err.println();
                                System.err.println(sf);
                                System.err.println();
                                System.err.println("More information: https://github.com/martinpaljak/cdoc/wiki/UnlimitedCrypto");
                                System.exit(2);
                            }
                        } else {
                            System.err.println("Please upgrade to Java 8 Update 151 or later");
                            System.err.println("More information: https://github.com/martinpaljak/cdoc/wiki/UnlimitedCrypto");
                            System.exit(2);
                        }
                    }
                }
            }

            if (args.has(OPT_VERBOSE)) {
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
            }

            if (args.has(OPT_DEBUG)) {
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
            }

            if (args.has(OPT_VERSION)) {
                System.out.println("# CDOC " + getVersion() + " with cdoc4j/" + CDOC.getLibraryVersion());
                System.out.println("# " + System.getProperty("java.version") + " by " + System.getProperty("java.vendor"));
            }

            // Add allowed issuers
            HashSet<X509Certificate> issuers = new HashSet<>();

            if (args.has(OPT_ISSUER)) {
                Path issuer = (Path) args.valueOf(OPT_ISSUER);
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                try (InputStream in = Files.newInputStream(issuer)) {
                    X509Certificate issuercrt = (X509Certificate) fact.generateCertificate(in);
                    issuers.add(issuercrt);
                }
            } else {
                // Or use built-ins.
                issuers.addAll(get_builtin_issuers());
            }

            // List issuers if asked
            for (X509Certificate issuer : issuers) {
                verbose("Allowed issuer: " + issuer.getSubjectDN());
            }

            // The total list of certificates to encrypt against.
            HashSet<X509Certificate> recipients = new HashSet<>();

            // Handle recipients from explicit command line
            if (args.has(OPT_RECIPIENT)) {
                for (Path pem : recipient_pems.values(args)) {
                    CertificateFactory fact = CertificateFactory.getInstance("X.509");
                    try (InputStream in = Files.newInputStream(pem)) {
                        X509Certificate recipient = (X509Certificate) fact.generateCertificate(in);
                        recipients.add(recipient);
                    }
                }
            }

            List<String> rest = args.valuesOf(others);
            List<Path> files = new ArrayList<>();
            HashSet<String> codes = new HashSet<>();
            for (String arg : rest) {
                Path f = Paths.get(arg);
                if (Files.isRegularFile(f)) {
                    files.add(f);
                } else if (IDCode.check(arg)) {
                    codes.add(arg);
                } else {
                    fail(arg + " is not a file nor ID-code!");
                }
            }

            // One-shot ops
            if (args.has(OPT_LIST)) {
                for (Path p : files) {
                    File f = p.toFile();
                    CDOC c = CDOC.open(f);
                    System.out.println(f.getName() + ": " + c.getVersion() + " with " + c.getAlgorithm());
                    for (Recipient r : c.getRecipients()) {
                        System.out.println("Encrypted for: " + (r.getName() == null ? "undisclosed recipient" : r.getName()) + " (" + r.getType() + ")");
                    }
                }
            }

            // Minimal
            if (files.size() == 0 && !args.has(OPT_VERSION)) {
                fail("Need files to encrypt or decrypt!");
            }

            // No ID codes with privacy mode
            if (args.has(OPT_PRIVACY) && codes.size() > 0) {
                fail("Do not use ID-codes in privacy mode, specify receiver with -r!");
            }

            // Resolve certificates from LDAP
            for (String code : codes) {
                Collection<X509Certificate> c = LDAP.fetch(code);
                if (args.has(OPT_VERBOSE) || c.size() == 0)
                    verbose("LDAP returned " + c.size() + " certificates for " + code);
                if (c.size() > 0) {
                    // Always filter LDAP certs
                    Collection<X509Certificate> uc = filter_crypto_certs(c);
                    verbose(uc.size() + " certificates are usable for encryption");
                    recipients.addAll(uc);
                } else {
                    if (!args.has(OPT_FORCE)) {
                        fail("LDAP returned no certificates for " + code);
                    } else {
                        System.err.println("Removing " + code + " from recipients, no certificates");
                    }
                }
            }

            // Filter recipients by type, unless force
            if (!args.has(OPT_FORCE)) {
                recipients = new HashSet<>(filter_crypto_certs(recipients));
            }

            // Finally filter by allowed issuers
            recipients = new HashSet<>(filter_issuers(recipients, issuers, args.has(OPT_FORCE)));

            // TODO: Warn about weak RSA recipients
            for (X509Certificate r : recipients) {
//            if (BrokenKey.isAffected(r)) {
//                System.err.println("WARNING: " + LDAP.cert2subjectmap(r).get("CN") + " is a weak key!");
//            }
            }

            // Count number of CDOC-s
            int num_cdocs = 0;
            for (Path p : files) {
                if (p.toString().toLowerCase().endsWith(".cdoc")) {
                    num_cdocs++;
                }
            }

            for (X509Certificate c : recipients) {
                verbose("Encrypting for " + c.getSubjectDN());
            }

            // DWIM
            if (recipients.size() == 0 && num_cdocs == files.size()) {
                // If all files are cdoc, decrypt them all
                File output = new File(".");
                if (args.has(OPT_OUT)) {
                    output = ((Path) args.valueOf(OPT_OUT)).toFile();
                }

                if (!output.isDirectory()) {
                    fail("-o must point to a directory, when decrypting");
                }

                for (Path p : files) {
                    try (CDOC cdoc = CDOC.open(p.toFile())) {
                        final SecretKey key;
                        Key dwim = dwimKey((String) args.valueOf(OPT_KEY));
                        if (dwim instanceof SecretKey) {
                            key = (SecretKey) dwim;
                        } else if (dwim instanceof PrivateKey) {
                            key = Decrypt.getKey((PrivateKey) dwim, cdoc.getRecipients().get(0), cdoc.getAlgorithm()); // FIXME
                        } else {
                            throw new IllegalStateException("Unknown argument passed: " + args.valueOf(OPT_KEY));
                        }
                        verbose("Using key: " + HexUtils.bin2hex(key.getEncoded()));
                        Map<String, byte[]> decrypted = cdoc.getFiles(key);
                        for (Map.Entry<String, byte[]> e : decrypted.entrySet()) {
                            File of = new File(output, e.getKey());
                            if (of.exists() && !args.has(OPT_FORCE))
                                fail("Output file " + of + " already exists");
                            verbose("Saving " + of);
                            Files.write(of.toPath(), e.getValue());
                        }
                    } catch (IOException e) {
                        // Do not fail if decryption is not possible
                        if (!args.has(OPT_LIST))
                            fail("Could not decrypt file: " + e.getMessage());
                    }
                }
                System.exit(0);
            } else {
                // There are recipients (or a key), thus we encrypt
                if (recipients.size() == 0) {
                    if (!args.has(OPT_CDOCV2)) {
                        fail("must specify recipients for encryption");
                    } else {
                        if (!args.has(OPT_KEY))
                            fail("must specify either recipients or a statid pre-shared key for encryption");
                    }
                }
                // Check if -o is present
                final File outfile;
                if (files.size() > 1) {
                    if (!args.has(OPT_OUT))
                        fail("need to use -o with multiple input files");
                    File o = ((Path) args.valueOf(OPT_OUT)).toFile();
                    if (o.isDirectory())
                        fail("can't use a directory as output, when there are multiple input files");
                    outfile = o;
                } else {
                    // Single file
                    String fn = args.has(OPT_PRIVACY) ? "encrypted.cdoc" : files.get(0).getFileName() + ".cdoc";
                    if (args.has(OPT_OUT)) {
                        File o = ((Path) args.valueOf(OPT_OUT)).toFile();
                        if (o.isDirectory()) {
                            outfile = new File(o, fn);
                        } else {
                            outfile = o;
                        }
                    } else {
                        outfile = new File(fn);
                    }
                }

                if (outfile.exists() && !args.has(OPT_FORCE))
                    fail("Output file " + outfile + " already exists");

                CDOCBuilder cdoc = CDOC.builder();

                // Version
                if (args.has(OPT_CDOCV2)) {
                    cdoc.setVersion(CDOC.Version.CDOC_V2_0);
                } else if (args.has(OPT_LEGACY)) {
                    cdoc.setVersion(CDOC.Version.CDOC_V1_0);
                }

                // Key
                if (args.has(OPT_KEY)) {
                    Key key = dwimKey((String) args.valueOf(OPT_KEY));
                    if (key instanceof SecretKey) {
                        System.out.println("Using static key: " + HexUtils.bin2hex(key.getEncoded()));
                        cdoc.withTransportKey((SecretKey) key);
                    } else {
                        fail("Must specify a secret key with -key when encrypting");
                    }
                }

                // Recipients
                for (X509Certificate r : recipients) {
                    cdoc.addRecipient(r);
                }

                // Source files
                for (Path p : files) {
                    cdoc.addPath(p);
                }

                // XML validation
                if (args.has(OPT_VALIDATE)) {
                    cdoc.withValidation(true);
                }

                // Privacy mode
                if (args.has(OPT_PRIVACY)) {
                    cdoc.withPrivacy(true);
                }

                // Shoot
                cdoc.buildToStream(Files.newOutputStream(outfile.toPath()));
                System.out.println("Saved encrypted file to " + outfile);
                System.exit(0);
            }
        } catch (IOException e) {
            fail("I/O Error: " + e.getMessage());
        } catch (IllegalStateException e) {
            fail("Can not run: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            fail("Illegal argument: " + e.getMessage());
        }
    }

    static Key dwimKey(String v) {
        File f = new File(v);
        if (f.isFile()) {
            try (PEMParser pem = new PEMParser(Files.newBufferedReader(f.toPath(), StandardCharsets.UTF_8))) {
                Object x = pem.readObject();
                if (x instanceof PEMKeyPair) {
                    PEMKeyPair kp = (PEMKeyPair) x;
                    // Make a private key
                    return new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
                } else {
                    fail("-key only supports plain PEM keypairs");
                    return null; // Static code analyzer
                }
            } catch (IOException e) {
                throw new IllegalArgumentException("Could not parse key: " + e.getMessage(), e);
            }
        } else {
            // Assume it is an AES key
            // TODO: check for validity before
            return new SecretKeySpec(HexUtils.stringToBin(v), "AES");
        }
    }
//
//    static SecretKey bruteforce(Collection<Recipient> recipients, boolean debug, EncryptionMethod em) throws CardException {
//        // If all recipients have a certificate, be smart with locating the right card
//        boolean nocert = false;
//        HashSet<X509Certificate> certs = new HashSet<>();
//        for (Recipient r : recipients) {
//            if (r.getCertificate() == null) {
//                nocert = true;
//            } else {
//                certs.add(r.getCertificate());
//            }
//        }
//
//        try {
//            if (!nocert) {
//                try (EstEID eid = EstEID.locateOneOf(certs)) {
//                    if (eid == null)
//                        throw new CardNotPresentException("Did not find a card");
//                    X509Certificate c = eid.getAuthCert();
//                    System.out.println("You are " + eid);
//                    Console console = System.console();
//                    char[] pinchars = console.readPassword("Enter PIN1: ");
//                    if (pinchars == null) {
//                        fail("PIN is null :(");
//                    }
//                    String pin = new String(pinchars);
//                    // Locate matching recipient
//                    for (Recipient r : recipients) {
//                        if (r.getCertificate().equals(c)) {
//                            if (r.getType() == Recipient.TYPE.RSA) {
//                                byte[] plaintext = eid.decrypt(r.getCryptogram(), pin);
//                                return new SecretKeySpec(plaintext, "AES");
//                            } else if (r.getType() == Recipient.TYPE.EC) {
//                                Recipient.ECDHESRecipient er = (Recipient.ECDHESRecipient) r;
//                                byte[] secret = eid.dh(er.getSenderPublicKey(), pin);
//                                return Decrypt.getKey(secret, er, em);
//                            }
//                        }
//                    }
//                }
//            } else {
//                try (EstEID eid = EstEID.anyCard()) {
//                    if (eid == null)
//                        throw new CardNotPresentException("Did not find a card");
//                    System.out.println("You are " + eid);
//                    X509Certificate authcert = eid.getAuthCert();
//
//                    // Check if we have a possibility to successfully decrypt
//                    boolean canDecrypt = false;
//                    for (Recipient r : recipients) {
//                        if (r.getType() == Recipient.TYPE.RSA && authcert.getPublicKey().getAlgorithm().equals("RSA")) {
//                            canDecrypt = true;
//                            break;
//                        }
//                        if (r.getType() == Recipient.TYPE.EC && authcert.getPublicKey().getAlgorithm().equals("EC")) {
//                            canDecrypt = true;
//                            break;
//                        }
//                    }
//                    if (!canDecrypt) {
//                        fail("Can't decrypt: chosen card has " + authcert.getPublicKey().getAlgorithm() + " keys, but none of the recipients has the same");
//                    }
//
//                    Console console = System.console();
//                    char[] pinchars = console.readPassword("Enter PIN1: ");
//                    if (pinchars == null) {
//                        System.err.println("PIN is null :(");
//                        System.exit(1);
//                    }
//                    String pin = new String(pinchars);
//                    for (Recipient r : recipients) {
//                        // If recipient has a certificate, compare and fail early.
//                        if (r.getCertificate() != null) {
//                            if (!r.getCertificate().getPublicKey().equals(authcert.getPublicKey())) {
//                                continue;
//                            }
//                        }
//                        // Otherwise bruteforce
//                        try {
//                            if (r.getType() == Recipient.TYPE.RSA && authcert.getPublicKey().getAlgorithm().equals("RSA")) {
//                                byte[] plaintext = eid.decrypt(r.getCryptogram(), pin);
//                                return new SecretKeySpec(plaintext, "AES");
//                            } else if (r.getType() == Recipient.TYPE.EC && authcert.getPublicKey().getAlgorithm().equals("EC")) {
//                                Recipient.ECDHESRecipient er = (Recipient.ECDHESRecipient) r;
//                                byte[] secret = eid.dh(er.getSenderPublicKey(), pin);
//                                return Decrypt.getKey(secret, er, em);
//                            } else {
//                                System.out.println("Algorithms do not match, trying next recipient ...");
//                            }
//                        } catch (InvalidKeyException e) {
//                            System.out.println("Did not decrypt, trying next recipient ...");
//                            continue;
//                        }
//                    }
//                    throw new IllegalStateException("Could not brute-decrypt key for any recipient");
//                }
//            }
//        } catch (CardException | EstEID.EstEIDException | GeneralSecurityException | EstEID.WrongPINException e) {
//            throw new CardException("Card communication error: " + e.getMessage());
//        }
//        throw new IllegalStateException("Could not decrypt a key for any recipient");
//    }

    static String getVersion() {
        String version = "unknown-development";
        try (InputStream versionfile = Tool.class.getResourceAsStream("pro_version.txt")) {
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, StandardCharsets.UTF_8))) {
                    version = vinfo.readLine();
                }
            }
        } catch (IOException e) {
            version = "unknown-error";
        }
        return version;
    }

    /**
     * Return a list of hard-coded X509 certificates
     */
    static Set<X509Certificate> get_builtin_issuers() {
        Set<X509Certificate> s = new HashSet<>();
        String[] builtins = new String[]{"ESTEID-SK_2011.pem.crt", "ESTEID-SK_2015.pem.crt", "esteid2018.pem.crt"};
        for (String c : builtins) {
            try (InputStream i = Tool.class.getResourceAsStream(c)) {
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                s.add((X509Certificate) fact.generateCertificate(i));
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException("Could not load built-in issuers", e);
            }
        }
        return s;
    }

    static X509Certificate issued_by(X509Certificate cert, Collection<X509Certificate> issuers) {
        for (X509Certificate issuer : issuers) {
            try {
                cert.verify(issuer.getPublicKey());
                return issuer;
            } catch (GeneralSecurityException e) {
                continue;
            }
        }
        return null;
    }

    // XXX: This is highly Estonia specific
    static Collection<X509Certificate> filter_crypto_certs(Collection<X509Certificate> certs) {
        ArrayList<X509Certificate> result = new ArrayList<>();
        for (X509Certificate c : certs) {
            String s = c.getSubjectX500Principal().toString();
            // Skip non-repudiation
            if (c.getKeyUsage()[1])
                continue;
            // Skip Mobile ID
            if (s.contains("MOBIIL-ID"))
                continue;
            result.add(c);
        }
        return result;
    }

    static Collection<X509Certificate> filter_issuers(Collection<X509Certificate> certs, Collection<X509Certificate> issuers, boolean ignoreVerification) {
        ArrayList<X509Certificate> result = new ArrayList<>();
        for (X509Certificate cert : certs) {
            if (issued_by(cert, issuers) == null && !ignoreVerification) {
                System.err.println(cert.getIssuerX500Principal().toString() + " verification failed!");
                continue;
            } else {
                result.add(cert);
            }
        }
        return result;
    }

    static void verbose(String s) {
        if (args.has(OPT_VERBOSE))
            System.out.println(s);
    }

    static void fail(String message) {
        System.err.println("Error: " + message);
        System.exit(1);
    }
}
