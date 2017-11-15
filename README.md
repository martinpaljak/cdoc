# idcrypt &nbsp; [![Build Status](https://travis-ci.org/martinpaljak/idcrypt.svg?branch=master)](https://travis-ci.org/martinpaljak/idcrypt) [![Latest release](https://img.shields.io/github/release/martinpaljak/idcrypt.svg)](https://github.com/martinpaljak/idcrypt/releases/latest) [![GPL-3.0 licensed](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/martinpaljak/idcrypt/blob/master/LICENSE)

CDOC command line utility - encrypt and decrypt files

## Usage
 * Decrypt a file

        cdoc <file.cdoc>

 * Encrypt a file

        cdoc <file>

 * Encrypt a file to yourself and Martin, with ID-code 38207162722
 
        cdoc <file> 38207162722

 * Encrypt two files to two persons, writing the output to somefile.cdoc

        cdoc file1.txt file2.txt 38207162722 38207162766 -o somefile.cdoc
 
 * If all arguments are existing files or valid ID-codes, they are used as intended.
 * Multiple input files mandate the use of -o

## Similar projects
 * qdigidoc
   * :) has a GUI  
   * :( only supports CDOC 1.0
 * GnuPG
   * :) widely supported format
   * :( only "web of trust" input for keys
   * :( cumbersome access to on-card keys (http://gnupg-pkcs11.sourceforge.net/)
