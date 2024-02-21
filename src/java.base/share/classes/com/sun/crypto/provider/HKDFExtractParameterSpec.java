package com.sun.crypto.provider;

import javax.crypto.SecretKey;
import java.util.Objects;

public final class HKDFExtractParameterSpec extends HKDFParameterSpec {
    private final SecretKey salt;
    private final SecretKey inputKey;

    public HKDFExtractParameterSpec(String hashAlg, SecretKey salt, SecretKey inputKey, String keyAlg) {
        super(hashAlg, keyAlg);
        this.salt = Objects.requireNonNull(salt);
        this.inputKey = Objects.requireNonNull(inputKey);
    }

    public SecretKey getSalt() {
        return salt;
    }

    public SecretKey getInputKey() {
        return inputKey;
    }
}
