package sun.security.pkcs11.wrapper;

/**
 * This class represents the necessary parameters required by
 * the CKM_HKDF_DERIVE mechanism as defined in CK_HKDF_PARAMS structure.<p>
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_HKDF_PARAMS {
 *   CK_BBOOL bExtract;
 *   CK_BBOOL bExpand;
 *   CK_MECHANISM_TYPE prfHashMechanism;
 *   CK_ULONG ulSaltType;
 *   CK_BYTE_PTR pSalt;
 *   CK_ULONG ulSaltLen;
 *   CK_OBJECT_HANDLE hSaltKey;
 *   CK_BYTE_PTR pInfo;
 *   CK_ULONG ulInfoLen;
 * } CK_HKDF_PARAMS;
 * </PRE>
 */
public class CK_HKDF_PARAMS {
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BBOOL bExtract;
     * </PRE>
     */
    public boolean bExtract;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BBOOL bExpand;
     * </PRE>
     */
    public boolean bExpand;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_MECHANISM_TYPE prfHashMechanism;
     * </PRE>
     */
    public long prfHashMechanism;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulSaltType;
     * </PRE>
     */
    public long ulSaltType;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BYTE_PTR pSalt;
     *   CK_ULONG ulSaltLen;
     * </PRE>
     */
    public byte[] pSalt;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_OBJECT_HANDLE hSaltKey;
     * </PRE>
     */
    public long hSaltKey;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BYTE_PTR pInfo;
     *   CK_ULONG ulInfoLen;
     * </PRE>
     */
    public byte[] pInfo;

}
