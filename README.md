# WIP, master may not be usable
# idcrypt · [![Build Status](https://travis-ci.org/martinpaljak/idcrypt.svg?branch=master)](https://travis-ci.org/martinpaljak/idcrypt) [![Latest release](https://img.shields.io/github/release/martinpaljak/idcrypt/all.svg)](https://github.com/martinpaljak/idcrypt/releases/latest) [![GPL-3.0 licensed](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/martinpaljak/idcrypt/blob/master/LICENSE)

CDOC command line utility - encrypt files

## Usage
Substitute `cdoc` with `java -jar cdoc.jar` on Unix and `cdoc.exe` on Windows. Use `cdoc -help` to view all command line options.

 * Encrypt a file to Martin, with ID-code 38207162722 (fetched from LDAP)
 
        cdoc <file> 38207162722 # encrypted file is written to <file>.cdoc

 * Encrypt two files to two persons (Martin and "other"), writing the output to `secret.cdoc`

        cdoc file1.txt file2.txt 38207162722 -r other.pem -o secret.cdoc
 
 * ~~Decrypt a file~~ (currently broken)

        cdoc <file.cdoc> # decrypted files are saved to current directory, override with -o

 * Multiple input files mandate the use of `-o`

## Privacy considerations
Using an ID code means that the corresponding certificate must be queried from an online service. If you do not wish to leave traces of your encryption activities, DO NOT use ID code to automagically fetch the receiver certificate. Instead, ask for the certificate of the other party via some other channel and specify it with `-r <certificate.pem>`

Please note that the identity of the receiver (who is capable of decrypting the file) is stored in plaintext within the container.

## Security and compatibility when encrypting for Estonian ID card
Estonian ID cards have either 2048 bit RSA keys or 384 bit elliptic curve keys. On-card keys are used to protect the AES data encryption key, also known as transport key.

| Format   | Data encryption | Transport key encryption               | Wire format   | Comments           |
|:---------|:----------------|:---------------------------------------|:--------------|:-------------------|
| CDOC 1.0 | AES-128 CBC     | RSA 2048 PKCS#1 v1.5                   | XML (Base64)  | **DEPRECATED**     |
| CDOC 1.1 | AES-256 GCM     | RSA 2048 PKCS#1 v1.5                   | XML (Base64)  | Best compatibility |
| CDOC 1.1 | AES-256 GCM     | ECDH-ES secp384r1 <br> AES-256 Key Wrap| XML (Base64)  | Best compatibility |
| CDOC 2.0 | AES-256 GCM     | RSA 2048 PKCS#1 v1.5                   | ODF (ZIP)     | Recommended        |
| CDOC 2.0 | AES-256 GCM     | ECDH-ES secp384r1 <br> AES-256 Key Wrap| ODF (ZIP)     | Recommended        |

At this moment (16 Nov 2017), the software available for Estonian ID-card from [installer.id.ee](https://installer.id.ee) supports only CDOC 1.0. Support for CDOC 1.1 is planned. Status of CDOC 2.0 plans is unknown.

Thus, when using CDOC 2.0 encryption format (with `-2`) the receiver must also use this utility for decryption. Usage of CDOC 2.0 is recommended, as it produces _significantly_ smaller files than CDOC 1.x.

The default format is CDOC 1.1. To force the usage of the deprecated CDOC 1.0 version, specify `-legacy`.

## Similar projects
 * qdigidoc
   * :) has a GUI  
   * :( only supports CDOC 1.0
 * GnuPG
   * :) widely supported format
   * :( only "web of trust" input for keys
   * :( cumbersome access to on-card keys (http://gnupg-pkcs11.sourceforge.net/)
