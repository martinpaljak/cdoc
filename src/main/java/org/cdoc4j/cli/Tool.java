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
import org.cdoc4j.CDOC;
import org.cdoc4j.CDOCBuilder;
import org.cdoc4j.Decrypt;
import org.cdoc4j.Recipient;
import org.esteid.EstEID;
import org.esteid.EstEID.PersonalData;
import org.esteid.IDCode;
import org.esteid.sk.LDAP;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardNotPresentException;
import javax.smartcardio.CardTerminal;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Tool {
    private static final String OPT_VERSION = "version";
    private static final String OPT_DECRYPT = "decrypt";
    private static final String OPT_KEY = "key";
    private static final String OPT_CDOCV2 = "cdoc2";
    private static final String OPT_OUT = "out";
    private static final String OPT_ENCRYPT = "encrypt";
    private static final String OPT_LEGACY = "legacy";
    private static final String OPT_VERBOSE = "verbose";
    private static final String OPT_FORCE = "force";
    private static final String OPT_ISSUER = "issuer";
    private static final String OPT_RECIPIENT = "receiver";
    private static final String OPT_VALIDATE = "validate";
    private static final String OPT_PRIVACY = "privacy";
    private static final String OPT_LIST = "list";


    private static OptionSet args = null;

    public static void main(String[] argv) throws Exception {
        // Prefer BouncyCastle
        //Security.insertProviderAt(new BouncyCastleProvider(), 0);

        OptionParser parser = new OptionParser();

        // Generic options
        parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show version");
        parser.acceptsAll(Arrays.asList("?", "help"), "Show this help");
        parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose");
        parser.acceptsAll(Arrays.asList("f", OPT_FORCE), "Force operation, omitting checks");
        parser.acceptsAll(Arrays.asList("d", OPT_DECRYPT), "Decrypt a file").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("k", OPT_KEY), "Use key to decrypt").withRequiredArg();
        parser.acceptsAll(Arrays.asList("o", OPT_OUT), "Save output to").withRequiredArg().withValuesConvertedBy(new PathConverter());
        parser.acceptsAll(Arrays.asList("e", OPT_ENCRYPT), "Encrypt a file").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("i", OPT_ISSUER), "Allowed issuer certificate").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("p", OPT_PRIVACY), "Respect privacy");
        parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List recipients").withRequiredArg();
        parser.acceptsAll(Arrays.asList("2", OPT_CDOCV2), "Create a CDOC 2.0 file");
        parser.accepts(OPT_VALIDATE, "Validate container or XML").withOptionalArg().describedAs(".cdoc");
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
                System.out.println("WARNING: Unlimited crypto policy is NOT installed!");
                System.out.println("Please read: https://github.com/martinpaljak/cdoc/wiki/UnlimitedCrypto");
                System.exit(2);
            }

            if (args.has(OPT_VERBOSE)) {
                String level = "debug";
                if (args.hasArgument(OPT_VERBOSE))
                    level = (String) args.valueOf(OPT_VERBOSE);
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level);
            }

            if (args.has(OPT_VERSION)) {
                System.out.println("# CDOC " + getVersion() + " with cdoc4j/" + CDOC.getLibraryVersion());
            }

            // One-shot ops
            if (args.has(OPT_LIST)) {
                File f = new File((String) args.valueOf(OPT_LIST));
                CDOC c = CDOC.open(f);
                System.out.println(c.getVersion() + " with " + c.getAlgorithm());
                for (Recipient r : c.getRecipients()) {
                    System.out.println("Encrypted for: " + (r.getName() == null ? "undisclosed recipient" : r.getName()) + " (" + r.getType() + ")");
                }
                System.exit(0);
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

            // Minimal
            if (files.size() == 0) {
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
                }
            }

            // Filter recipients by type, unless force
            if (!args.has(OPT_FORCE)) {
                recipients = new HashSet<>(filter_crypto_certs(recipients));
            }

            // Finally filter by allowed issuers
            recipients = new HashSet<>(filter_issuers(recipients, issuers, args.has(OPT_FORCE)));

            for (X509Certificate c : recipients) {
                verbose("Encrypting for " + c.getSubjectDN());
            }

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

            // DWIM
            // No recipients
            if (recipients.size() == 0) {

                // If all files are cdoc, decrypt them all
                if (num_cdocs == files.size()) {
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
                            if (args.has(OPT_KEY)) {
                                Key dwim = dwimKey((String) args.valueOf(OPT_KEY));
                                if (dwim instanceof SecretKey) {
                                    key = (SecretKey) dwim;
                                } else if (dwim instanceof PrivateKey) {
                                    key = Decrypt.getKey((PrivateKey) dwim, cdoc.getRecipients().get(0)); // FIXME
                                } else {
                                    throw new IllegalStateException("Unknown argument passed");
                                }
                                verbose("Using key: " + HexUtils.bin2hex(key.getEncoded()));
                            } else {
                                key = bruteforce(cdoc.getRecipients());
                            }
                            Map<String, byte[]> decrypted = cdoc.getFiles(key);
                            for (Map.Entry<String, byte[]> e : decrypted.entrySet()) {
                                File of = new File(output, e.getKey());
                                if (of.exists() && !args.has(OPT_FORCE))
                                    fail("Output file " + of + " already exists");
                                verbose("Saving " + of);
                                Files.write(of.toPath(), e.getValue());
                            }
                        }
                    }
                    System.exit(1);
                } else {
                    fail("Need recipients, add with -r");
                }
            } else {
                // There are recipients, thus we encrypt
                // Check if -o is present
                if (files.size() > 1 && !args.has(OPT_OUT)) {
                    fail("need to use -o with multiple input files");
                }

                File output = new File("."); // Default is CWD
                if (args.has(OPT_OUT)) {
                    output = ((Path) args.valueOf(OPT_OUT)).toFile();
                }

                if (files.size() == 1) {
                    // One file MAY use -o (which MAY be a folder)
                    String fn = files.get(0).getFileName() + ".cdoc";
                    if (output.isDirectory())
                        output = new File(output, fn);
                    else
                        output = new File(fn);
                } else {
                    if (output.isDirectory())
                        fail("Output must point to a file");
                }

                if (output.exists() && !args.has(OPT_FORCE))
                    fail("Output file " + output + " already exists");

                verbose("Encrypting to " + output);

                CDOCBuilder cdoc = CDOC.builder();

                // Version
                if (args.has(OPT_CDOCV2)) {
                    cdoc.setVersion(CDOC.VERSION.CDOC_V2_0);
                } else if (args.has(OPT_LEGACY)) {
                    cdoc.setVersion(CDOC.VERSION.CDOC_V1_0);
                }

                // Key
                if (args.has(OPT_KEY)) {
                    byte[] key = HexUtils.stringToBin((String) args.valueOf(OPT_KEY));
                    System.out.println("Using static key: " + HexUtils.bin2hex(key));
                    cdoc.withTransportKey(key);
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
                cdoc.buildToStream(Files.newOutputStream(output.toPath()));
                System.exit(0);
            }
        } catch (IOException e) {
            System.err.println("I/O Error: " + e.getMessage());
            System.exit(1);
        } catch (IllegalStateException e) {
            System.err.println("Can not run: " + e.getMessage());
            System.exit(1);
        } catch (IllegalArgumentException e) {
            System.err.println("Illegal argument: " + e.getMessage());
            System.exit(1);
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

    static SecretKey bruteforce(Collection<Recipient> recipients) throws IOException {
        Card card = null;
        try {
            CardTerminal ct = EstEID.get();
            card = ct.connect("*");
            card.beginExclusive();
            EstEID eid = EstEID.getInstance(card.getBasicChannel());
            String idcode = eid.getPersonalData(PersonalData.PERSONAL_ID);
            System.out.println("You are " + idcode);
            Console console = System.console();
            char[] pinchars = console.readPassword("Enter PIN1: ");
            if (pinchars == null) {
                System.err.println("PIN is null :(");
                System.exit(1);
            }
            X509Certificate authcert = eid.readAuthCert();
            String pin = new String(pinchars);
            for (Recipient r : recipients) {
                // If recipient has a certificate, compare and fail early.
                if (r.getCertificate() != null) {
                    if (!r.getCertificate().getPublicKey().equals(authcert.getPublicKey())) {
                        continue;
                    }
                }

                // Otherwise bruteforce
                try {
                    if (r.getType() == Recipient.TYPE.RSA) {
                        byte[] plaintext = eid.decrypt(r.getCryptogram(), pin);
                        return new SecretKeySpec(plaintext, "AES");
                    } else if (r.getType() == Recipient.TYPE.ECC) {
                        Recipient.ECDHESRecipient er = (Recipient.ECDHESRecipient) r;
                        // Do DH.
                        byte[] secret = eid.dh(er.getSenderPublicKey(), pin);
                        return Decrypt.getKey(secret, er);
                    }
                } catch (InvalidKeyException e) {
                    System.out.println("Did not decrypt, trying next recipient ...");
                    continue;
                }
            }
            throw new IllegalStateException("Could not brute-decrypt key for any recipient");
        } catch (CardNotPresentException e) {
            throw new IllegalStateException("No card: " + e.getMessage(), e);
        } catch (CardException | EstEID.EstEIDException e) {
            throw new IOException("Card communication error: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not brute-decrypt key: " + e.getMessage(), e);
        } catch (EstEID.WrongPINException e) {
            System.err.println("Incorrect pin: " + e.getMessage());
            throw new IllegalStateException("Incorrect PIN: " + e.getMessage(), e);
        } finally {
            if (card != null) {
                try {
                    card.endExclusive();
                    card.disconnect(true);
                } catch (CardException e) {
                    // Ignore
                }
            }
        }
    }


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
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            try (InputStream i = Tool.class.getResourceAsStream("ESTEID-SK_2011.pem.crt")) {
                s.add((X509Certificate) fact.generateCertificate(i));
            }
            try (InputStream i = Tool.class.getResourceAsStream("ESTEID-SK_2015.pem.crt")) {
                s.add((X509Certificate) fact.generateCertificate(i));
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Could not load built-in issuers", e);
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
            if (s.contains("MOBIIL-ID"))
                continue;
            if (!s.contains("authentication"))
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
