package com.icarus.ds;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;

public class Signer {

    public void sign(
            String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, MakeSignature.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Creating the appearance for lay 0
        PdfTemplate n0 = appearance.getLayer(0);
        float x = n0.getBoundingBox().getLeft();
        float y = n0.getBoundingBox().getBottom();
        float width = n0.getBoundingBox().getWidth();
        float height = n0.getBoundingBox().getHeight();
        n0.setColorFill(BaseColor.LIGHT_GRAY);
        n0.rectangle(x, y, width, height);
        n0.fill();
        // Creating the appearance for layer 2
        PdfTemplate n2 = appearance.getLayer(2);
        ColumnText ct = new ColumnText(n2);
        ct.setSimpleColumn(n2.getBoundingBox());
        Paragraph p = new Paragraph("This document was signed by Bruno Specimen.");
        ct.addElement(p);
        ct.go();
        // Creating the signature
        ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(
                appearance, digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args)
            throws GeneralSecurityException, IOException, DocumentException {
        String src = "src/main/resources/hello.pdf";
        String name = "sig";
        String dest = "results/chapter2/hello_signed.pdf";
        String keystore = "src/main/resources/ks";
        char[] pass = "password".toCharArray();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), pass);
        Certificate[] chain = ks.getCertificateChain("demo");
        PrivateKey pk = (PrivateKey) ks.getKey("demo", pass);
        String reason = "Test";
        String location = "Ghent";
        Signer signer = new Signer();
        signer.sign(src, name, dest, chain, pk, DigestAlgorithms.SHA256,
                provider.getName(), MakeSignature.CryptoStandard.CMS, reason, location);
    }

}
