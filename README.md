# idcrypt &nbsp; [![Build Status](https://travis-ci.org/martinpaljak/idcrypt.svg?branch=master)](https://travis-ci.org/martinpaljak/idcrypt)
CDOC command line utility - encrypt and decrypt files against personal ID code

## Usage
 * Fix a CDOC (replacing certificates where public key matches)

        idcrypt -fix <file.cdoc>

 * Decrypt a file

        idcrypt -d <file>

 * Encrypt a file (to yourself)

        idcrypt -e <file>

 * Encrypt a file to yourself and Martin, with ID-code 38207162722
 
        idcrypt -e <file> -r 38207162722

 * Encrypt two files to two persons, writing the output to somefile.cdoc

        idcrypt file1.txt file2.txt 38207162722 38207162766 -o somefile.cdoc
 
 * If all arguments are existing files or valid ID-codes, they are used as intended.
 * Multiple input files mandate the use of -o

## Similar projects
 * qdigidoc
   * :) has a GUI  
   * :( only supports CDOC 1.0 (see above)
 * GnuPG
   * :) widely supported format
   * :( only "web of trust" input for keys
   * :( cumbersome access to on-card keys (http://gnupg-pkcs11.sourceforge.net/)
