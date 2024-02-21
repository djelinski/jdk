package com.sun.crypto.provider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public class HKDFGenerator extends KeyGeneratorSpi {
    private static final String MSG = "HKDFGenerator must be " +
            "initialized using a HKDFParameterSpec";
    private SecretKey secret;

    @Override
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);

    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof HKDFParameterSpec hParams)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        String hashAlg = hParams.getHashAlg();
        Objects.requireNonNull(hashAlg,
                "Must provide underlying HKDF Digest algorithm.");
        String hmacAlg = "Hmac" + hashAlg.replace("-", "");
        Mac hmacObj;
        try {
            hmacObj = Mac.getInstance(hmacAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmParameterException("Unsupported hash algorithm: " + hashAlg, e);
        }
        int hmacLen = hmacObj.getMacLength();
        secret = switch (hParams) {
            case HKDFExtractParameterSpec hExtract -> {
                try {
                    hmacObj.init(hExtract.getSalt());
                } catch (InvalidKeyException e) {
                    throw new InvalidAlgorithmParameterException("The provided salt is not valid", e);
                }

                yield new SecretKeySpec(hmacObj.doFinal(hExtract.getInputKey().getEncoded()),
                        hExtract.getKeyAlg());

            }
            case HKDFExpandParameterSpec hExpand -> {
                byte[] kdfOutput;

                // Output from the expand operation must be <= 255 * hmac length
                if (hExpand.getOutLen() > 255 * hmacLen) {
                    throw new IllegalArgumentException("Requested output length " +
                            "exceeds maximum length allowed for HKDF expansion");
                }
                try {
                    hmacObj.init(hExpand.getPseudoRandKey());
                } catch (InvalidKeyException e) {
                    throw new InvalidAlgorithmParameterException("The provided PRK is not valid", e);
                }
                byte[] info = hExpand.getInfo();
                if (info == null) {
                    info = new byte[0];
                }
                int rounds = (hExpand.getOutLen() + hmacLen - 1) / hmacLen;
                kdfOutput = new byte[rounds * hmacLen];
                int offset = 0;
                int tLength = 0;

                for (int i = 0; i < rounds ; i++) {

                    // Calculate this round
                    try {
                        // Add T(i).  This will be an empty string on the first
                        // iteration since tLength starts at zero.  After the first
                        // iteration, tLength is changed to the HMAC length for the
                        // rest of the loop.
                        hmacObj.update(kdfOutput,
                                Math.max(0, offset - hmacLen), tLength);
                        hmacObj.update(info);                       // Add info
                        hmacObj.update((byte)(i + 1));              // Add round number
                        hmacObj.doFinal(kdfOutput, offset);

                        tLength = hmacLen;
                        offset += hmacLen;                       // For next iteration
                    } catch (ShortBufferException sbe) {
                        // This really shouldn't happen given that we've
                        // sized the buffers to their largest possible size up-front,
                        // but just in case...
                        throw new RuntimeException(sbe);
                    }
                }

                yield new SecretKeySpec(kdfOutput, 0, hExpand.getOutLen(), hExpand.getKeyAlg());
            }
        };

    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        return secret;
    }
}
