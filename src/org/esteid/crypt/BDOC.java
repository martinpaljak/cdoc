package org.esteid.crypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class BDOC {

	private static class UsefulZipEntry {
		ZipEntry e;
		byte [] d;
	}

	public static void fix(InputStream in, OutputStream out) throws IOException {
		// Do nothing currently, just add the
		BDOC b = new BDOC();
		ZipInputStream zin = new ZipInputStream(in, Charset.forName("Cp437"));
		HashMap <String, UsefulZipEntry> zips = new HashMap<>();
		ZipEntry ent = zin.getNextEntry();
		while (ent != null) {
			UsefulZipEntry ue = new UsefulZipEntry();
			ue.e = ent;
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] buf = new byte[1024];
			int c;
			while ((c = zin.read(buf)) > 0) {
				bos.write(buf, 0, c);
			}
			ue.d = bos.toByteArray();

			zips.put(ent.getName(), ue);
			System.out.println(ent.getName());
			ent = zin.getNextEntry();
		}


		ZipOutputStream zos = new ZipOutputStream(out, StandardCharsets.UTF_8);
		// Store them back in right order etc.
		UsefulZipEntry mimetype = zips.remove("mimetype");
		mimetype.e.setMethod(ZipEntry.STORED);
		mimetype.e.setSize(mimetype.d.length);
		zos.putNextEntry(mimetype.e);
		zos.write(mimetype.d);

		// Rest of the entries
		for (UsefulZipEntry e: zips.values()) {
			zos.putNextEntry(e.e);
			zos.write(e.d);
			zos.closeEntry();
		}
		zos.close();
	}
}
