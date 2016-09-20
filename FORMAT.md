# CDOC 2.0 specification
> DRAFT v0.2 20-09-2016, martin.paljak@eesti.ee

## Introduction
The main goals of CDOC v2.0 format over [CDOC v1.0](https://github.com/martinpaljak/idcrypt/wiki/CDOC-1.0) are resource-effectiveness when processing containers (less XML parsing), compatibility with ASiC-E (based on OpenDocument v1.2 ZIP packages) and general alignment with newer and future algorithms.

It defines and clarifies the subset of relevant standards and provides guidelines and requirements for compliant implementations.

## References
- [OpenDocument v1.2 part 3: packages](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html)
- [ETSI TS 102 918 V1.3.1 (ASiC)](http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf)
- [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core/)
- [XML Encryption Syntax and Processing Version 1.1](https://www.w3.org/TR/xmlenc-core1/)
- [XML Signature Syntax and Processing (Second Edition)](https://www.w3.org/TR/xmldsig-core/)
- [RFC 6931](https://tools.ietf.org/html/rfc6931)


## Overview
CDOC v2.0 files are essentially [OpenDocument v1.2](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html) containers, conforming to [OpenDocument Extended Package](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#__RefHeading__752793_826425813). The mime type is `application/x-cryptodoc` and recommended extension `.cdoc`.

Information about transport keys, recipients etc is stored in `META-INF/recipients.xml` which conforms to [XML-ENC](https://www.w3.org/TR/xmlenc-core/) standard and schema.

## Package requirements
* The mime type of CDOC v2.0 is `application/x-cryptodoc`
* The file extension SHOULD be `.cdoc`
* The `mimetype` file MUST be present, together with the `media-type` manifest element for the package (See [OpenDocument: 3.3 MIME Media Type](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#MIME_type_stream))
* The format MAY be used with ZIP64 extension.
* Storage of encrypted files MUST follow the rules laid down in [OpenDocument section 3.4.1](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#__RefHeading__752813_826425813), regarding deflation before storage and actual size in manifest.
* Multiple encrypted files MUST be encapsulated as ZIP containers, which implementations MAY display as sparse files after encryption


## Implementation requirements
* Implementations SHOULD support ZIP64 for files larger than 4GB
  * Lack of support for ZIP64 MUST be documented in accompanying documentation
* Implementations SHOULD allow to decrypt files which lack proper MIME information
* Formatting of encrypted files (IV, padding, authentication tags etc) MUST conform to XML-ENC

## Samples of `META-INF/recipients.txt`

### Encryption of a single file with a pre-shared key
`READMe.txt` is encrypted with AES-GCM 256 and the key itself is supposedly known to the receiver via ot of band means

```
<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#' MimeType="text/plain" />
   <EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes256-gcm'/>
   <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
     <ds:KeyName>The pre-shared key</ds:KeyName>
   </ds:KeyInfo>
   <CipherData><CipherReference URI="README.txt"/></CipherData>
</EncryptedData>
```

### Encryption of a single file with a certificate
The file `Important.bdoc` is encrypted with AES-256 in GCM mode. The transport key is encrypted with RSA PKCS#1 and the resulting cryptogram is included.

```
<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#' MimeType="application/vnd.etsi.asic-e+zip"/>
   <EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes256-gcm'/>
   <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
     <EncryptedKey Recipient="PALJAK,MARTIN,38207162722,DIGI-ID">
       <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
       <ds:KeyInfo>
         <ds:X509Data>
           <ds:X509Certificate>MIIE6...</ds:X509Certificate>
         </ds:X509Data>
       </ds:KeyInfo>
       <CipherData>
         <CipherValue>h3SJo...</CipherValue>
       </CipherData>
     </EncryptedKey>
   </ds:KeyInfo>
   <CipherData><CipherReference URI="Important.bdoc"/></CipherData>
</EncryptedData>
```
## Transition tips
- v2.0 has the bytes `PK` as the first two bytes of the file
- v1.0 has the XML header `<?` or relevant BOM in the first bytes of the file
