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
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
			dbf.setNamespaceAware(true);
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
		return get_recipients(doc); 
	}

	public Map<String, byte[]> decrypt(byte [] key) throws XPathExpressionException, GeneralSecurityException, CDOCExcption {
		if (key.length != 16) {
			throw new CDOCExcption("Invalid key", new IllegalArgumentException("Key size must be 16 bytes"));
		}
		String mime = doc.getDocumentElement().getAttributes().getNamedItem("MimeType").getTextContent();
		byte [] payload = get_encrypted_content();
		byte [] plaintext = decrypt(payload, key);
		// Special case for multiple files.
		if (mime.equals("http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")) {
			// This is a stupid case where the actual payload contains an unsigned .ddoc that contains the interesting files
			return get_files(plaintext);
		} else {
			String fname = xPath.evaluate("/denc:EncryptedData/denc:EncryptionProperties/denc:EncryptionProperty[@Name='Filename']", doc);
			// Make up a map
			Map<String, byte[]> f = new HashMap<>();
			f.put(fname, plaintext);
			return f;
		}
	}

	public static Map<String, byte[]> get_recipients(Document doc) throws CDOCExcption {
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

	// Decrypt with the required padding fixes
	public static byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException, XPathExpressionException {
		Cipher c = Cipher.getInstance("AES/CBC/NoPadding"); 
		// first 16 bytes of crypted payload is actually IV
		byte [] iv = Arrays.copyOf(data, 16);
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
		byte [] decr = c.doFinal(Arrays.copyOfRange(data, 16, data.length));
		// Last block is garbage, discard
		decr = Arrays.copyOf(decr, decr.length-16);
		// Remove padding
		//System.out.println(HexUtils.bin2hex(Arrays.copyOfRange(decr, decr.length-16, decr.length)));
		int padlen = decr[decr.length-1];
		decr = Arrays.copyOf(decr, decr.length - padlen);
		// Now clean.
		return decr;
	}

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
			System.out.println("Stored " + fn.getAbsolutePath());
			out.close();
		}
	}
}
