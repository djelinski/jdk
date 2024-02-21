package com.sun.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public abstract sealed class HKDFParameterSpec implements AlgorithmParameterSpec
        permits HKDFExtractParameterSpec, HKDFExpandParameterSpec {
    private final String keyAlg;
    private final String hashAlg;

    protected HKDFParameterSpec(String hashAlg, String keyAlg) {
        this.hashAlg = Objects.requireNonNull(hashAlg);
        this.keyAlg = Objects.requireNonNull(keyAlg);
    }

    public String getHashAlg() {
        return hashAlg;
    }

    public String getKeyAlg() {
        return keyAlg;
    }
}
