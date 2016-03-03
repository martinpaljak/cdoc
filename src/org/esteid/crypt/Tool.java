package org.esteid.crypt;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.naming.NamingException;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;

import org.esteid.EstEID;
import org.esteid.EstEID.PersonalData;
import org.esteid.EstEID.WrongPINException;
import org.esteid.crypt.CDOC.CDOCExcption;

import apdu4j.HexUtils;
import apdu4j.TerminalManager;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

public class Tool {
	private static final String OPT_VERSION = "version";
	private static final String OPT_FIX = "fix";
	private static final String OPT_DECRYPT = "decrypt";
	private static final String OPT_OUT = "out";
	private static final String OPT_ENCRYPT = "encrypt";
	private static final String OPT_CDOC = "cdoc";
	private static final String OPT_SEARCH = "search";

	public static void main(String[] argv) throws Exception {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show version");
		parser.acceptsAll(Arrays.asList("f", OPT_FIX), "Fix a CDOC").withRequiredArg().ofType(File.class);
		parser.acceptsAll(Arrays.asList("d", OPT_DECRYPT), "Decrypt a file").withRequiredArg().ofType(File.class);
		parser.acceptsAll(Arrays.asList("o", OPT_OUT), "Save output to").withRequiredArg();
		parser.acceptsAll(Arrays.asList("e", OPT_ENCRYPT), "Encrypt a file").withRequiredArg();
		parser.acceptsAll(Arrays.asList("s", OPT_SEARCH), "Search certificates based on ID-code").withRequiredArg();
		parser.accepts(OPT_CDOC, "Generate CDOC 1.0 format");

		OptionSpec<String> others = parser.nonOptions("args");

		// Parse arguments
		try {
			args = parser.parse(argv);
			// Try to fetch all values so that format is checked before usage
			for (String s: parser.recognizedOptions().keySet()) {args.valuesOf(s);}
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
			System.out.println("IDCrypt " + getVersion());
		}

		Set<X509Certificate> issuers = get_issuers();

		if (args.has(OPT_SEARCH)) {
			List<String> codes = (List<String>) args.valuesOf(OPT_SEARCH);
			for (String code: codes) {
				Map<String, X509Certificate> m = LDAP.get_certs(code);
				for (Map.Entry<String, X509Certificate> e: m.entrySet()) {
					X509Certificate cert = e.getValue();
					X509Certificate issuer = issued_by(cert, issuers);
					Map<String, String> n = LDAP.cert2subjectmap(cert);
					if (issuer == null) {
						System.out.println(n.get("CN") + " is invalid!");
					} else {
						Map<String, String> cn = LDAP.cert2subjectmap(issuer);
						System.out.println(n.get("CN") + " issued by " + cn.get("CN"));
					}
				}
			}
		}
		if (args.has(OPT_FIX)) {
			File f = (File) args.valueOf(OPT_FIX);
			if (!f.isFile()) {
				System.err.println("-f(ix) must address a file!");
			}
			CDOC c = CDOC.fromFile(f.getAbsolutePath());
			Card esteid = get_esteid();
			EstEID eid = EstEID.getInstance(esteid.getBasicChannel());
			X509Certificate cert = eid.readAuthCert();
			System.out.println("Right certificate has serial " + cert.getSerialNumber().toString(16));
			byte[] fixed = CDOC.fix(c, cert);

			File of;
			if (args.has(OPT_OUT)) {
				of = (File)args.valueOf(OPT_OUT);
			} else {
				of = f;
			}

			File tmp = File.createTempFile(f.getName(), "fix", f.getParentFile());
			try (FileOutputStream fos = new FileOutputStream(tmp)) {
				fos.write(fixed);
			}
			// Replace
			Files.move(tmp.toPath(), of.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
		} else if (args.has(OPT_DECRYPT)) {
			File fin = (File) args.valueOf(OPT_DECRYPT);
			if (!fin.isFile()) {
				System.err.println("Must reference a file with -d(ecrypt)!");
				System.exit(1);
			}
			File fout = new File(".");
			if (args.has(OPT_OUT)) {
				fout = new File((String)args.valueOf(OPT_OUT));
				if (!fout.exists()) {
					fout.mkdirs();
				}
				if (!fout.isDirectory()) {
					System.err.println("Must reference a directory with -o(out) when -d(ecrypt)-ing!");
					System.exit(1);
				}
			}
			decrypt_cdoc(fin, fout);
		} else {
			// Process rest
			List<String> rest = args.valuesOf(others);
			List<File> files = new ArrayList<>();
			List<String> codes = new ArrayList<>();
			for (String arg: rest) {
				File f = new File(arg);
				if (f.isFile()) {
					files.add(f);
					System.out.println(arg + " is a file");
				} else if (IDCode.is_valid_idcode(arg)) {
					codes.add(arg);
					System.out.println(arg + " is an idcode");
				}  else {
					System.err.println(arg + " is not a file nor ID-code!");
					System.exit(1);
				}
			}
			if (files.size() == 0) {
				System.err.println("No input files!");
				System.exit(1);
			}

			List<X509Certificate> recipients = get_crypto_certs(codes);

			// Encrypting
			if (recipients.size() > 0) {
				if (!args.has(OPT_OUT)) {
					System.err.println("Need -o(ut) with multiple input files!");
					System.exit(1);
				}

				File fout = new File((String)args.valueOf(OPT_OUT));
				if (fout.exists()) {
					System.out.println("Output file " + fout.getName() + " exists!");
					System.exit(1);
				}
				byte [] cryptodoc = CDOC.encrypt(files, recipients);
				try (FileOutputStream fos = new FileOutputStream(fout)) {
					fos.write(cryptodoc);
				}
				System.out.println("Stored to " + fout.getCanonicalPath());
			} else {
				System.out.println("Use -d to decrypt");
				System.exit(0);
			}
		}
	}

	public static List<X509Certificate> get_crypto_certs(List<String> codes) {
		List<X509Certificate> certs = new ArrayList<>();
		Set<X509Certificate> issuers = get_issuers();
		for (String code: codes) {
			try {
				Map<String, X509Certificate> m = LDAP.get_certs(code);
				for(Map.Entry<String, X509Certificate> k: m.entrySet()) {
					if (k.getKey().contains("MOBIIL-ID")) {
						continue;
					}
					if (!k.getKey().contains("authentication")) {
						continue;
					}
					if (issued_by(k.getValue(), issuers) == null) {
						System.err.println(k.getKey() + " verification failed!");
						continue;
					}
					certs.add(k.getValue());
				}
			} catch (GeneralSecurityException | NamingException e) {
				System.out.println("Exception, ignoring " + code);
			}
		}
		return certs;
	}

	public static void decrypt_cdoc(File fin, File fout) throws FileNotFoundException, CDOCExcption, IOException {
		Map<String, byte[]> files;

		CDOC cdoc = CDOC.fromFile(fin.getCanonicalPath());
		Map<String, byte[]> keys = cdoc.get_recipients();
		Card card = null;
		boolean success = false;
		try {
			card = get_esteid();
			card.beginExclusive();
			EstEID eid = EstEID.getInstance(card.getBasicChannel());
			String idcode = eid.getPersonalData(PersonalData.PERSONAL_ID);
			System.out.println("You are " + idcode);
			final String pin;
			for (Entry<String, byte[]> e: keys.entrySet()) {
				if (e.getKey().contains(idcode)) {
					System.out.println("Decrypting with " + e.getKey());
					// FIXME: pinpad
					Console console = System.console();
					char[] pinchars = console.readPassword("Enter PIN1: ");
					if (pinchars == null) {
						System.err.println("PIN is null :(");
						System.exit(1);
					}
					pin  = new String(pinchars);
					System.out.println("Decrypt payload: " + HexUtils.bin2hex(e.getValue()));
					byte [] key = eid.decrypt(e.getValue(), pin);
					files = cdoc.decrypt(key);
					for (Map.Entry<String, byte[]> entry: files.entrySet()) {
						File fput = new File(fout, new File(entry.getKey()).getName());
						try (FileOutputStream fos = new FileOutputStream(fput)) {
							fos.write(entry.getValue());
						}
						System.out.println("Saved to " + fput.getCanonicalPath() + " " + entry.getValue().length +  " bytes");
					}
					success = true;
					break;
				}
			}
		} catch (CardException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (WrongPINException e) {
			System.err.println("Incorrect pin: " + e.getMessage());
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
		CardTerminals cts = TerminalManager.getTerminalFactory().terminals();
		for (CardTerminal t: cts.list(State.CARD_PRESENT)) {
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
		try (InputStream versionfile = Tool.class.getResourceAsStream("version.txt")) {
			if (versionfile != null) {
				try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile))) {
					version = vinfo.readLine();
				}
			}
		} catch (IOException e) {
			version = "unknown-error";
		}
		return version;
	}

	public static Set<X509Certificate> get_issuers() {
		Set<X509Certificate> s = new HashSet<>();
		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate cert1 = (X509Certificate) fact.generateCertificate(Tool.class.getResourceAsStream("ESTEID-SK_2011.pem.crt"));
			X509Certificate cert2 = (X509Certificate) fact.generateCertificate(Tool.class.getResourceAsStream("ESTEID-SK_2015.pem.crt"));
			s.add(cert1);
			s.add(cert2);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return s;
	}

	public static X509Certificate issued_by(X509Certificate cert, Set<X509Certificate> issuers) {
		for (X509Certificate issuer: issuers) {
			try {
				cert.verify(issuer.getPublicKey());
				return issuer;
			} catch (GeneralSecurityException e) {
				continue;
			}
		}
		return null;
	}
}
