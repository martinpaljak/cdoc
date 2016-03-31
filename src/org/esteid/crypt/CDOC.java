package org.esteid.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.util.Arrays;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSException;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class CDOC {

	@SuppressWarnings("serial")
	public static class CDOCExcption extends Exception {

		public CDOCExcption(String message, Exception cause) {
			super(message, cause);
		}

	}
	static final XPath xPath;
	static {
		final class NSContext implements NamespaceContext {
			private final Map<String, String> prefixes = new HashMap<String, String>();

			public NSContext(final Map<String, String> prefMap) {
				prefixes.putAll(prefMap);       
			}
			@Override
			public String getNamespaceURI(String prefix) {
				return prefixes.get(prefix);
			}
			@Override
			public String getPrefix(String uri) {
				throw new UnsupportedOperationException();
			}
			@SuppressWarnings("rawtypes")
			@Override
			public Iterator getPrefixes(String uri) {
				throw new UnsupportedOperationException();
			}
		}
		xPath= XPathFactory.newInstance().newXPath();
		@SuppressWarnings("serial")
		HashMap<String, String> prefixes = new HashMap<String, String>() {{
			put("ddoc", "http://www.sk.ee/DigiDoc/v1.3.0#");
			put("denc", "http://www.w3.org/2001/04/xmlenc#");
			put("ds", "http://www.w3.org/2000/09/xmldsig#");
		}};
		NSContext nsctx = new NSContext(prefixes);
		xPath.setNamespaceContext(nsctx);
	}

	private final File original;
	private final Document doc;

	private CDOC(Document indoc, File original) {
		this.doc = indoc;
		this.original = original;
	}
	public static CDOC fromFile(String path) throws FileNotFoundException, CDOCExcption {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setXIncludeAware(false);
			dbf.setExpandEntityReferences(false);
			dbf.setNamespaceAware(true);
			dbf.setFeature("http://xml.org/sax/features/validation", false);
			dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
			dbf.setFeature("http://apache.org/xml/features/validation/schema", false);
			dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new FileInputStream(path)));
			return new CDOC(doc, new File(path));
		} catch (ParserConfigurationException | SAXException | IOException e) {
			throw new CDOCExcption("Could not open CDOC", e);
		}
	}

	private byte[] get_encrypted_content() throws CDOCExcption {
		try {
			String s = xPath.evaluate("/denc:EncryptedData/denc:CipherData/denc:CipherValue", doc);
			byte[] data = Base64.getMimeDecoder().decode(s);
			return data;
		} catch (XPathException e) {
			throw new CDOCExcption("Could not extract payload", e);
		}
	}

	public Map<String, byte[]> get_recipients() throws CDOCExcption {
		try {
			HashMap<String, byte[]> result = new HashMap<>();
			NodeList nodes = (NodeList) xPath.evaluate("/denc:EncryptedData/ds:KeyInfo/denc:EncryptedKey", doc, XPathConstants.NODESET);
			for (int i = 0; i < nodes.getLength(); i++) {
				Node n = nodes.item(i);
				String key = xPath.evaluate("denc:CipherData/denc:CipherValue", n);
				result.put(n.getAttributes().getNamedItem("Recipient").getTextContent(), Base64.getMimeDecoder().decode(key));			
			}
			return result;
		} catch (XPathExpressionException e) {
			throw new CDOCExcption("Could not parse recipients", e);
		}
	}

	public Map<String, byte[]> decrypt(byte [] key) throws GeneralSecurityException, CDOCExcption {
		if (key.length != 16) {
			throw new CDOCExcption("Invalid key", new IllegalArgumentException("Key size must be 16 bytes"));
		}
		try {
			String mime = doc.getDocumentElement().getAttributes().getNamedItem("MimeType").getTextContent();
			byte [] payload = get_encrypted_content();
			byte [] plaintext = decrypt(payload, key);
			// Special case for multiple files.
			if (mime.equals("http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")) {
				// This is a stupid case where the actual payload contains an unsigned .ddoc that contains the interesting files
				return get_files(plaintext);
			} else {
				// Get the name of the file
				String fname = xPath.evaluate("/denc:EncryptedData/denc:EncryptionProperties/denc:EncryptionProperty[@Name='Filename']", doc);
				// FIXME: Filename vs orig_file when one is missing
				// Make up a map
				Map<String, byte[]> f = new HashMap<>();
				f.put(fname, plaintext);
				return f;
			}
		} catch (DOMException | XPathExpressionException e) {
			throw new CDOCExcption("Failed to parse", e);
		}
	}

	// Decrypt with the required padding fixes
	public static byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException, XPathExpressionException {
		Cipher c = Cipher.getInstance("AES/CBC/NoPadding"); 
		// first 16 bytes of crypted payload is actually IV
		byte [] iv = Arrays.copyOf(data, 16);
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
		byte [] decr = c.doFinal(Arrays.copyOfRange(data, 16, data.length));
		// Last block is always full block of PKCS#7 padding
		if (decr[decr.length-1] == 0x10) {	
			decr = Arrays.copyOf(decr, decr.length-16);
		}
		// Remove X923 padding
		int padlen = decr[decr.length-1];
		decr = Arrays.copyOf(decr, decr.length - padlen);
		// Now clean payload.
		return decr;
	}

	// Extracts a SignedDoc into files
	public static Map<String, byte[]> get_files(byte[] payload) throws GeneralSecurityException, XPathExpressionException {
		// Extract files from inner DDOC 1.3
		InputStream inner = new ByteArrayInputStream(payload);
		NodeList files = (NodeList) xPath.evaluate("/ddoc:SignedDoc/ddoc:DataFile", new InputSource(inner), XPathConstants.NODESET);
		// Collect files
		Map<String, byte[]> result = new HashMap<>();
		for (int i = 0; i < files.getLength(); i++) {
			Node n = files.item(i);
			byte [] bytes = Base64.getMimeDecoder().decode(n.getTextContent());
			result.put(n.getAttributes().getNamedItem("Filename").getTextContent(), bytes);
		}
		return result;
	}

	public static byte[] fix(CDOC cdoc, X509Certificate newcert) throws UnsupportedEncodingException, DOMException, LSException, CertificateException, XPathExpressionException {
		// Get all certificates
		NodeList certs = (NodeList) xPath.evaluate("/denc:EncryptedData/ds:KeyInfo/denc:EncryptedKey/ds:KeyInfo/ds:X509Data/ds:X509Certificate", cdoc.doc, XPathConstants.NODESET);
		CertificateFactory f = CertificateFactory.getInstance("X509");
		for (int i = 0; i < certs.getLength(); i++) {
			Node cert = certs.item(i);
			byte [] bytes = Base64.getMimeDecoder().decode(cert.getTextContent());
			X509Certificate crt = (X509Certificate) f.generateCertificate(new ByteArrayInputStream(bytes));
			if (((RSAPublicKey)crt.getPublicKey()).getModulus().equals(((RSAPublicKey)newcert.getPublicKey()).getModulus())) {
				if (crt.getSerialNumber().equals(newcert.getSerialNumber())) {
					System.out.println(cdoc.original.getName() + " is already up to date!");				
				} else {
					System.out.println("Replacing " + crt.getSerialNumber().toString(16) + " with " + newcert.getSerialNumber().toString(16));				
					cert.setTextContent(Base64.getEncoder().encodeToString(newcert.getEncoded()));
				}
			}
		}

		DOMImplementationLS domImplementation = (DOMImplementationLS) cdoc.doc.getImplementation();
		LSOutput lsOutput = domImplementation.createLSOutput();
		lsOutput.setEncoding("UTF-8");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		lsOutput.setByteStream(bos);
		LSSerializer lsSerializer = domImplementation.createLSSerializer();
		lsSerializer.write(cdoc.doc, lsOutput); 
		return bos.toByteArray();
	}

	public static void test_decrypt(String f, byte [] key) throws Exception {
		CDOC cdoc = CDOC.fromFile(f);
		Map<String, byte[]> files = cdoc.decrypt(key);
		for (Map.Entry<String, byte[]> entry: files.entrySet()) {
			File fn = new File("/tmp/" + entry.getKey());
			FileOutputStream out = new FileOutputStream(fn);
			out.write(entry.getValue());
			System.out.println("Stored " + fn.getCanonicalPath());
			out.close();
		}
	}
	// Generates a minimalistic SignedDoc that is OK for qdigidoccrypto
	public static byte [] files2xml(List<File> files) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document cdoc = db.newDocument();

		Node root = cdoc.createElement("SignedDoc");
		Node rootns = cdoc.createAttribute("xmlns");
		rootns.setTextContent("http://www.sk.ee/DigiDoc/v1.3.0#");
		root.getAttributes().setNamedItem(rootns);
		Node format = cdoc.createAttribute("format");
		format.setTextContent("DIGIDOC-XML");
		root.getAttributes().setNamedItem(format);
		Node version = cdoc.createAttribute("version");
		version.setTextContent("1.3");
		root.getAttributes().setNamedItem(version);
		cdoc.appendChild(root);
		root.appendChild(cdoc.createTextNode("\n"));
		// Files
		for (File f: files) {
			Node datafile = cdoc.createElement("DataFile");
			Node type = cdoc.createAttribute("ContentType");
			type.setTextContent("EMBEDDED_BASE64");
			datafile.getAttributes().setNamedItem(type);

			Node filename = cdoc.createAttribute("Filename");
			filename.setTextContent(f.getName());
			datafile.getAttributes().setNamedItem(filename);

			Node mimetype = cdoc.createAttribute("MimeType");
			mimetype.setTextContent("application/octet-stream");
			datafile.getAttributes().setNamedItem(mimetype);

			Node filesize = cdoc.createAttribute("Size");
			filesize.setTextContent(Long.toString(f.length()));
			datafile.getAttributes().setNamedItem(filesize);

			Node id = cdoc.createAttribute("Id");
			id.setTextContent("D" + files.indexOf(f));
			datafile.getAttributes().setNamedItem(id);

			datafile.setTextContent(Base64.getEncoder().encodeToString(Files.readAllBytes(f.toPath())));
			root.appendChild(datafile);
			root.appendChild(cdoc.createTextNode("\n"));
		}

		// Serialize
		DOMImplementationLS domImplementation = (DOMImplementationLS) cdoc.getImplementation();
		LSOutput lsOutput = domImplementation.createLSOutput();
		lsOutput.setEncoding("UTF-8");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		lsOutput.setByteStream(bos);
		LSSerializer lsSerializer = domImplementation.createLSSerializer();
		lsSerializer.write(cdoc, lsOutput); 
		return bos.toByteArray();
	}

	// FIXME: logical blocks
	public static byte[] encrypt(List<File> files, List<X509Certificate> recipients) throws Exception {
		byte [] data = files2xml(files);
		// Actual encryption bytes
		byte [] dek = new byte[16];
		SecureRandom.getInstanceStrong().nextBytes(dek); // CRITICAL
		// Encrypt payload
		data = encrypt(data, dek);
		// Cipher for KEK
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// Construct cdoc.
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document cdoc = db.newDocument();

		Node root = cdoc.createElement("denc:EncryptedData");
		Node rootns = cdoc.createAttribute("xmlns:denc");
		rootns.setTextContent("http://www.w3.org/2001/04/xmlenc#");
		root.getAttributes().setNamedItem(rootns);
		cdoc.appendChild(root);
		root.appendChild(cdoc.createTextNode("\n"));
		Node mimetype = cdoc.createAttribute("MimeType");
		mimetype.setTextContent("http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd");
		root.getAttributes().setNamedItem(mimetype);
		Node encmethod = cdoc.createElement("denc:EncryptionMethod");
		Node encalgorithm = cdoc.createAttribute("Algorithm");
		encalgorithm.setTextContent("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
		encmethod.getAttributes().setNamedItem(encalgorithm);
		root.appendChild(encmethod);
		root.appendChild(cdoc.createTextNode("\n"));
		// Key infos
		Node keyinfo = cdoc.createElement("ds:KeyInfo");
		Node keyns = cdoc.createAttribute("xmlns:ds");
		keyns.setTextContent("http://www.w3.org/2000/09/xmldsig#");
		keyinfo.getAttributes().setNamedItem(keyns);
		root.appendChild(keyinfo);
		for (X509Certificate crt: recipients) {
			Node enckey = cdoc.createElement("denc:EncryptedKey");
			Node recipient = cdoc.createAttribute("Recipient");
			// Get a nice name
			LdapName ldapDN = new LdapName(crt.getSubjectX500Principal().getName());
			HashMap<String, String> subj = new HashMap<>();
			for(Rdn rdn: ldapDN.getRdns()) {
				subj.put(rdn.getType(), rdn.getValue().toString());
			}
			recipient.setTextContent(subj.get("CN"));
			enckey.getAttributes().setNamedItem(recipient);
			// Encryption method
			Node kekmethod = cdoc.createElement("denc:EncryptionMethod");
			Node kekalgorithm = cdoc.createAttribute("Algorithm");
			kekalgorithm.setTextContent("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
			kekmethod.getAttributes().setNamedItem(kekalgorithm);
			enckey.appendChild(kekmethod);
			// Certificate
			Node kinfo = cdoc.createElement("ds:KeyInfo");
			Node x509data = cdoc.createElement("ds:X509Data");
			kinfo.appendChild(x509data);
			Node x509cert = cdoc.createElement("ds:X509Certificate");
			x509cert.setTextContent(Base64.getEncoder().encodeToString(crt.getEncoded()));
			x509data.appendChild(x509cert);
			enckey.appendChild(kinfo);
			// Add actual cipher value
			//keyinfo.appendChild(enckey);
			Node cipherdata = cdoc.createElement("denc:CipherData");
			Node ciphervalue = cdoc.createElement("denc:CipherValue");

			// Encrypt the dek for recipient with kek
			c.init(Cipher.ENCRYPT_MODE, crt.getPublicKey());
			ciphervalue.setTextContent(Base64.getEncoder().encodeToString(c.doFinal(dek)));
			cipherdata.appendChild(ciphervalue);

			enckey.appendChild(cipherdata);
			keyinfo.appendChild(enckey);
			keyinfo.appendChild(cdoc.createTextNode("\n"));

		}
		// Add payload
		Node cipherdata = cdoc.createElement("denc:CipherData");
		Node payload = cdoc.createElement("denc:CipherValue");
		payload.setTextContent(Base64.getEncoder().encodeToString(data));
		cipherdata.appendChild(payload);
		root.appendChild(cipherdata);
		root.appendChild(cdoc.createTextNode("\n"));

		// Add comments or file will not have content
		Node props = cdoc.createElement("denc:EncryptionProperties");
		for (File f: files) {
			Node prop = cdoc.createElement("denc:EncryptionProperty");
			Node propname = cdoc.createAttribute("Name");
			propname.setTextContent("orig_file");
			prop.getAttributes().setNamedItem(propname);
			prop.setTextContent("😳 - decrypt me!|1|application/octet-stream|D" + files.indexOf(f));
			props.appendChild(prop);
		}
		root.appendChild(props);

		// Serialize
		DOMImplementationLS domImplementation = (DOMImplementationLS) cdoc.getImplementation();
		LSOutput lsOutput = domImplementation.createLSOutput();
		lsOutput.setEncoding("UTF-8");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		lsOutput.setByteStream(bos);
		LSSerializer lsSerializer = domImplementation.createLSSerializer();
		lsSerializer.write(cdoc, lsOutput); 

		return bos.toByteArray();
	}

	public static byte[] encrypt(byte [] data, byte [] key) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance("AES/CBC/NoPadding"); 
		// Double padding
		byte [] pad = padpkcs7(padx923(data));
		// XXX first 16 bytes of "crypted payload" is actually plaintext IV
		byte [] iv = new byte[16];
		SecureRandom.getInstanceStrong().nextBytes(iv);
		c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
		byte [] cgram = c.doFinal(pad);
		// Prepend IV
		return concatenate(iv, cgram);
	}

	// FIXME: wrong place, bad implementation
	private static byte[] padx923(byte[] text) {
		int length = text.length;
		int blocksize = 16;
		int totalLength = length;
		for (totalLength++; (totalLength % blocksize) != 0; totalLength++);
		int padlength = totalLength - length;
		byte[] result = new byte[totalLength];
		System.arraycopy(text, 0, result, 0, length);
		for (int i = 0; i < padlength; i++) {
			result[length + i] = (byte) 0x00;
		}
		result[result.length-1] = (byte) padlength;
		return result;
	}

	private static byte[] padpkcs7(byte[] text) {
		int length = text.length;
		int blocksize = 16;
		int totalLength = length;
		for (totalLength++; (totalLength % blocksize) != 0; totalLength++);
		int padlength = totalLength - length;
		byte[] result = new byte[totalLength];
		System.arraycopy(text, 0, result, 0, length);
		for (int i = 0; i < padlength; i++) {
			result[length + i] = (byte) padlength;
		}
		return result;
	}

	static byte[] concatenate(byte[]... args) {
		int length = 0, pos = 0;
		for (byte[] arg : args) {
			length += arg.length;
		}
		byte[] result = new byte[length];
		for (byte[] arg : args) {
			System.arraycopy(arg, 0, result, pos, arg.length);
			pos += arg.length;
		}
		return result;
	}	
}
