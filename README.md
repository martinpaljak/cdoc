# idcrypt &nbsp; [![Build Status](https://travis-ci.org/martinpaljak/idcrypt.svg?branch=master)](https://travis-ci.org/martinpaljak/idcrypt)
Decrypt CDOC-s and encrypt files against personal ID code

## Usage
 * Fix a CDOC (replacing certificats where public key matches)

        idcrypt -fix <file.cdoc>

 * Decrypt a file (either a .cdoc or .idcrypt)

        idcrypt -d <file>

 * Encrypt a file (to yourself)

        idcrypt -e <file>

 * Encrypt a file to yourself and Martin, with ID-code 38207162722
 
        idcrypt -e <file> -r 38207162722

 * Encrypt two files to two persons, writing the output to somefile.idcrypt

        idcrypt file1.txt file2.txt 38207162722 38207162766 -o somefile.idcrypt 
 
 * If all arguments are existing files or valid ID-codes, they are used as intended.
 * Multiple input files mandate the use of -o
 * Use -s to split payload from keys when encrypting

## Notes and caveats
 * [CDOC 1.0 format](http://id.ee/public/SK-CDOC-1.0-20120625_EN.pdf) supports only AES-128 in CBC mode
 * CDOC 1.0 format does not mandate the use of MimeType (only way to distinguish an unsigned .ddoc inside payload) [spec](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-EncryptedType)
 * CDOC 1.0 format and implementations leak the original file name(s) by default
 * CDOC 1.0 format is not valid according to XML-ENC schema (content and attributes of denc:EncryptionProperty are invalid)
 * CDOC 1.0 implementation from libdigidoc actually has the plaintext IV in front of the payload inside CipherValue element (different from spec 4.3).
 * CDOC 1.0 implementations seem to use double padding: PKCS7PAD(X923PAD(payload))
 * idcrypt implementation of CDOC supports only the "ddoc inside cdoc" format, which is: content files base64-d, put inside SignedDoc/DataFile XML elements. The result is then encrypted and embedded inside a CDOC with a special MimeType attribute (in fact a URL to XML Schema). Only necessary (to make qdigidoccrypto recognize the content) non-standard "orig_file" elements inside denc:EncryptionProperty elements are generated with no names and original file sizes.
 * .idcrypt (CDOC 1.1 ?) format uses AES-256 in GCM mode by default (can override with -c)

## Similar projects
 * qdigidoc
   * :) has a GUI  
   * :( only supports CDOC 1.0 (see above)
 * GnuPG
   * :) widely supported format
   * :( only "web of trust" interface
