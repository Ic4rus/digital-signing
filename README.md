<h1 style="text-align: center">
    <a href="https://en.wikipedia.org/wiki/Digital_signature" title="Title">Digital Signature</a>
</h1>

## Overview

This example illustrates the sample codes of `iText`'s digital signatures solution.

Reference document:
- https://itextpdf.com/solutions/electronic-signatures-pdf
- https://itextpdf.com/sites/default/files/2018-12/digitalsignatures20130304.pdf

## Create a key store

```shell
$ keytool -genkey -alias demo -keyalg RSA -keysize 2048 -keystore ks
Enter keystore password:  
Re-enter new password: 
What is your first and last name?
  [Unknown]:  Bruno Specimen
What is the name of your organizational unit?
  [Unknown]:  IT
What is the name of your organization?
  [Unknown]:  iText Software
What is the name of your State or Province?
  [Unknown]:  OVL
What is the two-letter country code for this unit?
  [Unknown]:  BE
Is CN=Bruno Specimen, OU=IT, O=iText Software, L=Ghent, ST=OVL, C=BE correct?
  [no]:  yes

Enter key password for <demo>
        (RETURN if same as keystore password):

Warning:
The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using "keytool -importkeystore -srckeystore ks -destkeystore ks -deststoretype pkcs12".
```