package com.icarus.ds;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class SignHelloWorld {

    public void createPdf(String filename) throws IOException, DocumentException{
        // step 1: Create a Document
        Document document = new Document();
        // step 2: Create a PdfWriter
        PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(filename));
        // step 3: Open the Document
        document.open();
        // step 4: Add content
        document.add(new Paragraph("Hello World!"));
        // create a signature form field
        PdfFormField field = PdfFormField.createSignature(writer);
        // set the widget properties
        field.setPage();
        field.setWidget(new Rectangle(72, 732, 144, 780), PdfAnnotation.HIGHLIGHT_INVERT);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        // add it as an annotation
        writer.addAnnotation(field);
        // maybe you want to define an appearance
        PdfAppearance tp = PdfAppearance.createAppearance(writer, 72, 48);
        tp.setColorStroke(BaseColor.BLUE);
        tp.setColorFill(BaseColor.LIGHT_GRAY);
        tp.rectangle(0.5f, 0.5f, 71.5f, 47.5f);
        tp.fillStroke();
        tp.setColorFill(BaseColor.BLUE);
        ColumnText.showTextAligned(tp, Element.ALIGN_CENTER, new Phrase("SIGN HERE"), 36, 24, 25);
        field.setAppearance(PdfAnnotation.APPEARANCE_NORMAL, tp);
        // step 5: Close the Document
        document.close();
    }

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
        // Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(
                appearance, digest, signature, chain, null, null, null, 0, subfilter);
    }

}
