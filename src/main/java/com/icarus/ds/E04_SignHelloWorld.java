package com.icarus.ds;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class E04_SignHelloWorld extends SignHelloWorld {

    public static final String KEYSTORE = "src/main/resources/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "src/main/resources/hello.pdf";
    public static final String DEST = "results/chapter2/hello_signed.pdf";

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        SignHelloWorld app = new E04_SignHelloWorld();
        app.sign(
                SRC, "sig", DEST, chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                MakeSignature.CryptoStandard.CMS, "Test", "Ghent");
    }
}
