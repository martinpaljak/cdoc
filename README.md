# idcrypt
Decrypt CDOC-s and encrypt against personal ID code

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

## Notes and caveats
 * CDOC only supports AES-128 in CBC mode
 * CDOC format does not mandate the use of MimeType (only way to distinguish a signed .ddoc)

## Similar projects
 * qdigidoc
   * :) has a GUI  
   * :( only supports CDOC 1.0 (AES-128 in CBC mode)
 * GnuPG
   * :) widely supported format
   * :( only "web of trust" interface
