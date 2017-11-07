package org.esteid.cdoctool;

import apdu4j.HexUtils;
import apdu4j.TerminalManager;
import asic4j.Container;
import asic4j.ContainerFile;
import asic4j.ManifestEntry;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.PathConverter;
import joptsimple.util.PathProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.esteid.EstEID;
import org.esteid.EstEID.PersonalData;
import org.esteid.IDCode;
import org.esteid.cdoc.CDOC;
import org.esteid.cdoc.CDOCv2;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;

public class Tool {
    private static final String OPT_VERSION = "version";
    private static final String OPT_DECRYPT = "decrypt";
    private static final String OPT_KEY = "key";
    private static final String OPT_2 = "2";

    private static final String OPT_OUT = "out";
    private static final String OPT_ENCRYPT = "encrypt";
    private static final String OPT_LEGACY = "legacy";
    private static final String OPT_VERBOSE = "verbose";
    private static final String OPT_FORCE = "force";
    private static final String OPT_ISSUER = "issuer";
    private static final String OPT_RECIPIENT = "receiver";
    private static final String OPT_SANITIZE = "sanitize";
    private static final String OPT_SODOMIZE = "sodomize";


    public static void main(String[] argv) throws Exception {
        // Prefer BouncyCastle
        Security.insertProviderAt(new BouncyCastleProvider(), 0);

        OptionSet args = null;
        OptionParser parser = new OptionParser();

        // Generic options
        parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show version");
        parser.acceptsAll(Arrays.asList("h", "?", "help"), "Show this help");
        parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose");
        parser.acceptsAll(Arrays.asList("f", OPT_FORCE), "Force operation, omitting checks");
        parser.acceptsAll(Arrays.asList("d", OPT_DECRYPT), "Decrypt a file").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("k", OPT_KEY), "Use key to decrypt").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("o", OPT_OUT), "Save output to").withRequiredArg().withValuesConvertedBy(new PathConverter());
        parser.acceptsAll(Arrays.asList("e", OPT_ENCRYPT), "Encrypt a file").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.acceptsAll(Arrays.asList("i", OPT_ISSUER), "Allowed issuer certificate").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.accepts(OPT_SANITIZE, "Sanitize a XML container").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));
        parser.accepts(OPT_SODOMIZE, "Sodomize a ZIP container").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));

        // Type safety
        OptionSpec<Path> recipient_pems = parser.acceptsAll(Arrays.asList("r", OPT_RECIPIENT), "Receiving cert").withRequiredArg().withValuesConvertedBy(new PathConverter(PathProperties.FILE_EXISTING));

        // Weird things
        parser.accepts(OPT_LEGACY, "Generate legacy CDOC 1.0");
        parser.accepts(OPT_2, "Create CDOC 2.0 ZIP container");

        // The rest
        OptionSpec<String> others = parser.nonOptions("files and ID-codes");

        // Parse arguments
        try {
            args = parser.parse(argv);
            // Try to fetch all values so that format is checked before usage
            for (String s : parser.recognizedOptions().keySet()) {
                args.valuesOf(s);
            }
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

        if (args.has(OPT_VERSION)) {
            System.out.println("# IDCrypt " + getVersion());
        }

        // One-shot ops, sanitize and sodomize

        // Encryption and decryption

        // Add allowed issuers
        Set<X509Certificate> issuers = new HashSet<>();

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
        if (args.has(OPT_VERBOSE)) {
            for (X509Certificate issuer : issuers) {
                System.out.println("Allowed issuer: " + issuer.getSubjectX500Principal());
            }
        }

        // Sanitize ASiC container
        if (args.has(OPT_SANITIZE)) {
            Path f = (Path) args.valueOf(OPT_SANITIZE);
            ContainerFile initial = ContainerFile.open(f);
            List<String> errors = new ArrayList<>();
            initial.check(errors);

            Container fixed = new Container(initial.getMimeType());

            // Put the meta files
            for (String meta : initial.getMetaFiles()) {
                fixed.put_meta(meta, initial.get(meta));
            }

            // Put payload files, again.
            for (ManifestEntry pload : initial.getManifest().getFiles()) {
                fixed.put(pload.path, pload.mimetype, initial.get(pload.path));
            }

            // Create new container. By default, replace original file
            Path of = f;
            if (args.has(OPT_OUT)) {
                of = (Path) args.valueOf(OPT_OUT);
            }

            Path tmp = Files.createTempFile(f, "fix", "blah");
            tmp.toFile().deleteOnExit();
            try (OutputStream fos = Files.newOutputStream(tmp)) {
                fixed.write(fos);
            }
            // Replace
            Files.move(tmp, of, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            System.exit(0);
        }

        // Process arguments
        // Load a plaintext key for testing
        if (args.has(OPT_KEY)) {
            try (PEMParser pem = new PEMParser(new InputStreamReader(Files.newInputStream((Path) args.valueOf(OPT_KEY)), "UTF-8"))) {
                Object x = pem.readObject();
                if (x instanceof PEMKeyPair) {
                    PEMKeyPair kp = (PEMKeyPair) x;
                    System.out.println("pubkey " + kp.getPublicKeyInfo().getAlgorithm().getAlgorithm());

                    // Make a private key
                    PrivateKey jpk = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
                    System.out.println("privkey: " + jpk.getAlgorithm());
                } else {
                    System.err.println("-key only supports plain PEM keypairs");
                    System.exit(1);
                }
            }
        }

        // The total list of certificates to encrypt against.
        List<X509Certificate> recipients = new ArrayList<>();

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
        List<String> codes = new ArrayList<>();
        for (String arg : rest) {
            Path f = Paths.get(arg);
            if (Files.isRegularFile(f)) {
                files.add(f);
            } else if (IDCode.check(arg)) {
                codes.add(arg);
            } else {
                System.err.println(arg + " is not a file nor ID-code!");
                System.exit(1);
            }
        }

        // Minimal
        if (files.size() == 0) {
            System.err.println("Need files to encrypt or decrypt!");
            System.exit(1);
        }

        // Resolve codes from LDAP
        for (String code : codes) {
            System.out.println("Processing " + code);
        }

        // Filter recipients by type, unless force
        if (!args.has(OPT_FORCE)) {
            recipients = filter_crypto_certs(recipients);
        }

        // Finally filter by allowed issuers
        recipients = filter_issuers(recipients, issuers, args.has(OPT_FORCE));


        if (args.has(OPT_VERBOSE)) {
            for (X509Certificate c : recipients) {
                System.out.println("Encrypting to " + c.getSubjectDN());
            }
        }
        // Warn about weak recipients
        for (X509Certificate r : recipients) {
//            if (BrokenKey.isAffected(r)) {
//                System.err.println("WARNING: " + LDAP.cert2subjectmap(r).get("CN") + " is a weak key!");
//            }
        }

        // Count number of CDOC-s
        int num_cdocs = 0;
        // If all files are cdoc, decrypt them
        for (Path p : files) {
            if (p.toString().toLowerCase().endsWith(".cdoc")) {
                num_cdocs++;
            }
        }

        // DWIM
        // No recipients
        if (recipients.size() == 0) {
            // Decrypt all
            if (num_cdocs == files.size()) {
                System.out.println("Will try to decrypt all input files");
                return;
            }
            System.out.println("Need recipients");
        } else {
            System.out.println("Will encrypt all input files");

            // There are recipients, thus we can encrypt
            // Check if -o is present
            File output = new File("blah.cdoc");
            if (args.has(OPT_OUT)) {
                output = new File((String) args.valueOf(OPT_OUT));
            }

            // Convert
            List<File> f = new ArrayList<>();
            for (Path p : files) {
                f.add(p.toFile());
            }
            System.out.println("Writing to " + output);
            if (args.has(OPT_2))
                CDOCv2.encrypt(output, f, recipients);
            else
                CDOC.encrypt(output, f, recipients);
            System.exit(0);
        }


        // Decrypt files.
        if (args.has(OPT_DECRYPT) || args.has(OPT_KEY)) {
            // TODO: load key

            Path fin = (Path) args.valueOf(OPT_DECRYPT);
            if (!Files.isRegularFile(fin)) {
                System.err.println("Must reference a file with -d(ecrypt)!");
                System.exit(1);
            }
            // By default save to current folder.
            Path fout = Paths.get(".");
            if (args.has(OPT_OUT)) {
                fout = (Path) args.valueOf(OPT_OUT);
                if (!Files.exists(fout)) {
                    Files.createDirectories(fout);
                }
                if (!Files.isDirectory(fout)) {
                    System.err.println("Must reference a directory with -o(out) when -d(ecrypt)-ing!");
                    System.exit(1);
                }
            }

        }

    }


    public static void decrypt_cdoc(Path fin, Path fout) throws FileNotFoundException, IOException {
        Map<String, byte[]> files = new HashMap<>();

        //CDOC cdoc = CDOC.fromFile(fin);
        //Map<String, byte[]> keys = cdoc.get_recipients();
        Map<String, byte[]> keys = new HashMap<>();
        Card card = null;
        boolean success = false;
        try {
            card = get_esteid();
            card.beginExclusive();
            EstEID eid = EstEID.getInstance(card.getBasicChannel());
            String idcode = eid.getPersonalData(PersonalData.PERSONAL_ID);
            System.out.println("You are " + idcode);
            final String pin;
            for (Entry<String, byte[]> e : keys.entrySet()) {
                if (e.getKey().contains(idcode)) {
                    System.out.println("Decrypting with " + e.getKey());
                    // FIXME: pinpad
                    Console console = System.console();
                    char[] pinchars = console.readPassword("Enter PIN1: ");
                    if (pinchars == null) {
                        System.err.println("PIN is null :(");
                        System.exit(1);
                    }
                    System.out.println("Decrypt payload: " + HexUtils.bin2hex(e.getValue()));
                    //pin = new String(pinchars);
                    //byte[] key = eid.decrypt(e.getValue(), pin);
                    //files = cdoc.decrypt(key);
                    for (Map.Entry<String, byte[]> entry : files.entrySet()) {
                        Path fput = Paths.get(entry.getKey()).resolve(fout);
                        try (OutputStream fos = Files.newOutputStream(fput)) {
                            fos.write(entry.getValue());
                        }
                        System.out.println("Saved to " + fput + " " + entry.getValue().length + " bytes");
                    }
                    success = true;
                    break;
                }
            }
        } catch (CardException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } //catch (WrongPINException e) {
        //   System.err.println("Incorrect pin: " + e.getMessage());
        // }
        catch (EstEID.EstEIDException e) {
            e.printStackTrace();
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
        if (!success) {
            System.err.println("Failed to decrypt");
        }
    }

    // FIXME: select AID or something
    public static Card get_esteid() throws CardException, NoSuchAlgorithmException {
        CardTerminals cts = TerminalManager.getTerminalFactory(true).terminals();
        for (CardTerminal t : cts.list(State.CARD_PRESENT)) {
            Card c;
            try {
                c = t.connect("*");
                return c;
            } catch (CardException e) {
                continue;
            }
        }
        throw new IllegalStateException("This application expects an EstEID card but none is available!");
    }

    public static String getVersion() {
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
     *
     * @return
     */
    public static Set<X509Certificate> get_builtin_issuers() {
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

    static X509Certificate issued_by(X509Certificate cert, Set<X509Certificate> issuers) {
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
    static List<X509Certificate> filter_crypto_certs(List<X509Certificate> certs) {
        List<X509Certificate> result = new ArrayList<>();
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

    static List<X509Certificate> filter_issuers(List<X509Certificate> certs, Set<X509Certificate> issuers, boolean ignoreVerification) {
        List<X509Certificate> result = new ArrayList<>();
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
}
