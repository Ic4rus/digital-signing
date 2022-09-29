package com.icarus.ds;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.Security;

public class DigestBC extends DigestDefault {

    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    static {
        Security.addProvider(PROVIDER);
    }

    protected DigestBC(String password, String algorithm) throws GeneralSecurityException {
        super(password, algorithm, PROVIDER.getName());
    }

    public static DigestBC getInstance(String password, String algorithm, String provider)
            throws GeneralSecurityException {
        return new DigestBC(password, algorithm);
    }

    public static void main(String[] args) {
        showTest("MD5");
        showTest("SHA-1");
        showTest("SHA-224");
        showTest("SHA-256");
        showTest("SHA-384");
        showTest("SHA-512");
        showTest("RIPEMD128");
        showTest("RIPEMD160");
        showTest("RIPEMD256");
    }
}
