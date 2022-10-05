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
import java.util.Date;

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

    public void sign(
            int index, String reason, String location, int certificationLevel)
            throws IOException, DocumentException, GeneralSecurityException {
        String dest = String.format(this.dest, index);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(this.src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(this.signame);
        appearance.setCertificationLevel(certificationLevel);

        ExternalSignature pks = new PrivateKeySignature(this.pk, DigestAlgorithms.SHA256, this.provider.getName());
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(
                appearance, digest, pks, this.chain, null, null, null, 0,
                MakeSignature.CryptoStandard.CMS);
    }

    public void addWrongAnnotation() throws IOException, DocumentException {
        String src = "results/chapter2/hello_signed.pdf";
        String dest = "results/chapter2/hello_signed_wrong_annotation.pdf";
        PdfReader reader = new PdfReader(src);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest));
        PdfAnnotation comment = PdfAnnotation.createText(
                stamper.getWriter(), new Rectangle(200, 800, 250, 820), "Finally Signed!",
                "Bruno Specimen has finally signed the document", true, "Comment");
        stamper.addAnnotation(comment, 1);
        stamper.close();
    }

    public void addAnnotation() throws IOException, DocumentException {
        String src = "results/chapter2/hello_signed2.pdf";
        String dest = "results/chapter2/hello_signed2_annotated.pdf";
        PdfReader reader = new PdfReader(src);
        PdfStamper stamper =
                new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
        PdfAnnotation comment = PdfAnnotation.createText(stamper.getWriter(),
                new Rectangle(200, 800, 250, 820), "Finally Signed!",
                "Bruno Specimen has finally signed the document", true, "Comment");
        stamper.addAnnotation(comment, 1);
        stamper.close();
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        Signer signer = new Signer();
//        signer.sign(
//                1, "Test 1", "Ghent", PdfSignatureAppearance.NOT_CERTIFIED);
//        signer.sign(
//                2, "Test 2", "Ghent", PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
//        signer.sign(
//                3, "Test 3", "Ghent", PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
//        signer.sign(
//                4, "Test 4", "Ghent", PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
        signer.addAnnotation();
    }

}
