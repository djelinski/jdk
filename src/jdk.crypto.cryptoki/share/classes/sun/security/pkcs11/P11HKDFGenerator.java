package sun.security.pkcs11;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_HKDF_PARAMS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import com.sun.crypto.provider.HKDFExpandParameterSpec;
import com.sun.crypto.provider.HKDFExtractParameterSpec;
import com.sun.crypto.provider.HKDFParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

import static sun.security.pkcs11.TemplateManager.O_GENERATE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;

public class P11HKDFGenerator extends KeyGeneratorSpi {
    private static final String MSG = "P11HKDFGenerator must be " +
            "initialized using a HKDFParameterSpec";
    private final Token token;
    private final String algorithm;
    private final long mechanism;
    private SecretKey secret;

    public P11HKDFGenerator(Token token, String algorithm, long mechanism) {
        this.token = token;
        this.algorithm = algorithm;
        this.mechanism = mechanism;
    }

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
        CK_HKDF_PARAMS hkdfParams = new CK_HKDF_PARAMS();
        String keyAlg = hParams.getKeyAlg();
        boolean isIV = "TlsIv".equals(keyAlg);
        CK_MECHANISM ckMechanism = new CK_MECHANISM(isIV ? CKM_HKDF_DATA : CKM_HKDF_DERIVE, hkdfParams);
        int hmacLen;
        switch (hashAlg) {
            case "SHA-256", "SHA256" -> {
                hkdfParams.prfHashMechanism = CKM_SHA256_HMAC;
                hmacLen = 32;
            }
            case "SHA-384", "SHA384" -> {
                hkdfParams.prfHashMechanism = CKM_SHA384_HMAC;
                hmacLen = 48;
            }
            default ->
                throw new InvalidAlgorithmParameterException("Unsupported hash algorithm: " + hashAlg);
        }
        secret = switch (hParams) {
            case HKDFExtractParameterSpec hExtract -> {
                hkdfParams.bExtract = true;
                SecretKey saltKey = hExtract.getSalt();
                if (saltKey instanceof P11Key p11saltKey) {
                    hkdfParams.hSaltKey = p11saltKey.getKeyID();
                    hkdfParams.ulSaltType = CKF_HKDF_SALT_KEY;
                } else {
                    byte[] saltBytes = saltKey.getEncoded();
                    if (saltBytes != null) {
                        hkdfParams.pSalt = saltBytes;
                        hkdfParams.ulSaltType = CKF_HKDF_SALT_DATA;
                    } else {
                        throw new InvalidAlgorithmParameterException("Unsupported salt key type");
                    }
                }
                SecretKey inputKey = hExtract.getInputKey();
                long p11KeyID;
                if (inputKey instanceof P11Key p11inputKey) {
                    p11KeyID = p11inputKey.getKeyID();
                    try {
                        Session session = null;
                        try {
                            session = token.getObjSession();
                            CK_ATTRIBUTE[] attributes = token.getAttributes(O_GENERATE,
                                    CKO_SECRET_KEY, CKK_GENERIC_SECRET, new CK_ATTRIBUTE[]{
                                            new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
                                    });
                            long keyID = token.p11.C_DeriveKey(session.id(),
                                    ckMechanism, p11KeyID, attributes);
                            yield P11Key.secretKey(session, keyID,
                                    keyAlg, hmacLen << 3, attributes);
                        } catch (PKCS11Exception e) {
                            throw new ProviderException("Could not derive key", e);
                        } finally {
                            token.releaseSession(session);
                        }
                    } finally {
                        p11inputKey.releaseKeyID();
                    }
                } else {
                    byte[] inputKeyBytes = inputKey.getEncoded();
                    if (inputKeyBytes != null) {
                        CK_ATTRIBUTE[] inputAttributes = new CK_ATTRIBUTE[] {
                                new CK_ATTRIBUTE(CKA_CLASS, CKO_DATA),
                                new CK_ATTRIBUTE(CKA_VALUE, inputKeyBytes),
                        };
                        Session session = null;
                        try {
                            session = token.getObjSession();
                            p11KeyID = token.p11.C_CreateObject(session.id(), inputAttributes);
                            try {
                                CK_ATTRIBUTE[] attributes = token.getAttributes(O_GENERATE,
                                        CKO_SECRET_KEY, CKK_GENERIC_SECRET, new CK_ATTRIBUTE[]{
                                                new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
                                        });
                                long keyID = token.p11.C_DeriveKey(session.id(),
                                        ckMechanism, p11KeyID, attributes);
                                yield P11Key.secretKey(session, keyID,
                                        keyAlg, hmacLen << 3, attributes);
                            } finally {
                                token.p11.C_DestroyObject(session.id(), p11KeyID);
                            }
                        } catch (PKCS11Exception e) {
                            throw new ProviderException("Could not derive key", e);
                        } finally {
                            token.releaseSession(session);
                        }
                    } else {
                        throw new InvalidAlgorithmParameterException("Unsupported input key type");
                    }
                }
            }
            case HKDFExpandParameterSpec hExpand -> {
                hkdfParams.bExpand = true;
                hkdfParams.pInfo = hExpand.getInfo();
                SecretKey inputKey = hExpand.getPseudoRandKey();
                long p11KeyID;
                if (inputKey instanceof P11Key p11inputKey) {
                    p11KeyID = p11inputKey.getKeyID();
                    try {
                        Session session = null;
                        try {
                            session = token.getObjSession();
                            int outKeyLen = hExpand.getOutLen();
                            CK_ATTRIBUTE lenAttribute = new CK_ATTRIBUTE(CKA_VALUE_LEN, outKeyLen);
                            CK_ATTRIBUTE[] attributes;
                            if (isIV) {
                                attributes = new CK_ATTRIBUTE[]{lenAttribute};
                            } else {
                                attributes = token.getAttributes(O_GENERATE,
                                        CKO_SECRET_KEY, CKK_GENERIC_SECRET, new CK_ATTRIBUTE[]{
                                                new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                                                lenAttribute
                                        });
                            }
                            long keyID = token.p11.C_DeriveKey(session.id(),
                                    ckMechanism, p11KeyID, attributes);
                            if (isIV) {
                                // fake attributes - data object does not have these
                                attributes = new CK_ATTRIBUTE[] {
                                        new CK_ATTRIBUTE(CKA_TOKEN, false),
                                        new CK_ATTRIBUTE(CKA_SENSITIVE, false),
                                        new CK_ATTRIBUTE(CKA_EXTRACTABLE, true),
                                };
                            }
                            yield P11Key.secretKey(session, keyID,
                                    keyAlg, outKeyLen << 3, attributes);
                        } catch (PKCS11Exception e) {
                            throw new ProviderException("Could not derive key", e);
                        } finally {
                            token.releaseSession(session);
                        }
                    } finally {
                        p11inputKey.releaseKeyID();
                    }
                } else {
                    throw new InvalidAlgorithmParameterException("Unsupported input key type");
                }
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
