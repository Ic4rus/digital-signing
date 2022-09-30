package com.icarus.ds;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;

public class Signer {

    private String src = "src/main/resources/hello.pdf";
    private String dest = "results/chapter2/hello_signed%s.pdf";
    private String signame = "sig";
    private BouncyCastleProvider provider;
    private char[] password = "password".toCharArray();
    private Certificate[] chain;
    private PrivateKey pk;

    public Signer() throws GeneralSecurityException, IOException {
        this.provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream("src/main/resources/ks"), password);
        this.chain = ks.getCertificateChain("demo");
        this.pk = (PrivateKey) ks.getKey("demo", password);
    }

    public PdfSignatureAppearance createAppearance(String dest, String reason, String location)
            throws IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(this.src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(this.signame);
        return appearance;
    }

    public void sign1(String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        PdfSignatureAppearance appearance = createAppearance(String.format(this.dest, 1), reason, location);
        appearance.setLayer2Text("This document was singed by Bruno Specimen");
        appearance.setLayer2Font(new Font(Font.FontFamily.TIMES_ROMAN));
        sign(appearance);
    }

    public void sign2(String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        PdfSignatureAppearance appearance = createAppearance(String.format(this.dest, 2), reason, location);
        appearance.setLayer2Text("\u0644\u0648\u0631\u0627\u0646\u0633 \u0627\u0644\u0639\u0631\u0628");
        appearance.setRunDirection(PdfWriter.RUN_DIRECTION_RTL);
        appearance.setLayer2Font(new Font(
                BaseFont.createFont(
                        "src/main/resources/font/arialuni.ttf", BaseFont.IDENTITY_H, BaseFont.EMBEDDED)));
        sign(appearance);
    }

    public void sign3(String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        PdfSignatureAppearance appearance = createAppearance(String.format(this.dest, 3), reason, location);
        appearance.setImage(Image.getInstance("src/main/resources/image/wet-ink-signature.png"));
        appearance.setImageScale(1);
        sign(appearance);
    }

    public void sign4(String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        PdfSignatureAppearance appearance = createAppearance(String.format(this.dest, 4), reason, location);
        appearance.setImage(Image.getInstance("src/main/resources/image/wet-ink-signature.png"));
        appearance.setImageScale(-1);
        sign(appearance);
    }

    public void sign(PdfSignatureAppearance appearance)
            throws DocumentException, GeneralSecurityException, IOException {
        ExternalSignature pks = new PrivateKeySignature(this.pk, DigestAlgorithms.SHA256, this.provider.getName());
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(
                appearance, digest, pks, this.chain, null, null, null, 0,
                MakeSignature.CryptoStandard.CMS);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        Signer signer = new Signer();
        signer.sign1("Test 1", "Ghent");
        signer.sign2("Test 2", "Ghent");
        signer.sign3("Test 3", "Ghent");
        signer.sign4("Test 4", "Ghent");
    }

}
