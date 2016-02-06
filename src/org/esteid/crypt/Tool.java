package org.esteid.crypt;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;

import org.esteid.EstEID;
import org.esteid.EstEID.PersonalData;

import apdu4j.TerminalManager;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

public class Tool {
	private static final String OPT_FIX = "fix";
	private static final String OPT_DECRYPT = "decrypt";
	private static final String OPT_OUT = "out";

	public static void main(String[] argv) throws Exception {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.acceptsAll(Arrays.asList("f", OPT_FIX), "Fix a CDOC").withRequiredArg().ofType(File.class);
		parser.acceptsAll(Arrays.asList("d", OPT_DECRYPT), "Decrypt a file").withRequiredArg().ofType(File.class);
		parser.acceptsAll(Arrays.asList("o", OPT_OUT), "Save output to").withRequiredArg();

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
		}

		if (args.has(OPT_DECRYPT)) {
			Map<String, byte[]> files;
			File fin = (File) args.valueOf(OPT_DECRYPT);
			if (!fin.isFile()) {
				System.err.println("Must reference a file with -d(ecrypt)!");
				System.exit(1);
			}
			File fout = new File(".");
			if (args.has(OPT_OUT)) {
				fout = new File((String)args.valueOf(OPT_OUT));
				if (!fout.isDirectory()) {
					System.err.println("Must reference a directory with -o(out) when -d(ecrypt)-ing!");
					System.exit(1);
				}
			}
			CDOC cdoc = CDOC.fromFile(fin.getCanonicalPath());
			Map<String, byte[]> keys = cdoc.get_recipients();
			Card card = get_esteid();
			boolean success = false;
			try {
				card.beginExclusive();
				EstEID eid = EstEID.getInstance(card.getBasicChannel());
				String idcode = eid.getPersonalData(PersonalData.PERSONAL_ID);

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
			} finally {
				card.endExclusive();
			}
			if (!success) {
				System.err.println("Failed to decrypt");
			}
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
}
