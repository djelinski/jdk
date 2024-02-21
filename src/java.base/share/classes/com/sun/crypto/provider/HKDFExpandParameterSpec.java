package com.sun.crypto.provider;

import javax.crypto.SecretKey;
import java.util.Objects;

public final class HKDFExpandParameterSpec extends HKDFParameterSpec {
    private final SecretKey pseudoRandKey;
    private final byte[] info;
    private final int outLen;

    public HKDFExpandParameterSpec(String hashAlg, SecretKey pseudoRandKey, byte[] info, int outLen, String keyAlg) {
        super(hashAlg, keyAlg);
        this.pseudoRandKey = Objects.requireNonNull(pseudoRandKey);
        this.info = info;
        this.outLen = outLen;
    }

    public SecretKey getPseudoRandKey() {
        return pseudoRandKey;
    }

    public byte[] getInfo() {
        return info;
    }

    public int getOutLen() {
        return outLen;
    }
}
