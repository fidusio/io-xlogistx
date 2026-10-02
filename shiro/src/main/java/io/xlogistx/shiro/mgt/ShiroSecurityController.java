package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CipherCodecs;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APICredentialsDAO;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.crypto.EncryptedData;
import org.zoxweb.shared.crypto.EncapsulatedKey;
import org.zoxweb.shared.data.MessageTemplate;
import org.zoxweb.shared.filters.BytesValueFilter;
import org.zoxweb.shared.filters.ChainedFilter;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.ExceptionReason.Reason;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.UUID;

public class ShiroSecurityController
        implements SecurityController {

    public static final LogWrapper log = new LogWrapper(ShiroSecurityController.class).setEnabled(false);

    @Override
    public void validateCredential(CredentialInfo ci, String input) throws AccessSecurityException {

    }

    @Override
    public void validateCredential(CredentialInfo ci, byte[] input) throws AccessSecurityException {

    }

    @Override
    public final Object encryptValue(APIDataStore<?, ?> dataStore, NVEntity container, NVConfig nvc, NVBase<?> nvb, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters", container.getGUID(), nvb);


        boolean encrypt = false;
        boolean masked = false;

        // the nvpair filter will override nvc value
        if (nvb instanceof NVPair &&
                (ChainedFilter.isFilterSupported(((NVPair) nvb).getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(((NVPair) nvb).getValueFilter(), FilterType.ENCRYPT_MASK))) {
            encrypt = true;
            masked = ChainedFilter.isFilterSupported(((NVPair) nvb).getValueFilter(), FilterType.ENCRYPT_MASK);
        } else if (nvc != null && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK))) {
            encrypt = true;
            masked = ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK);
        }


        if (encrypt && nvb.getValue() != null) {
            // CRUD.MOVE was to allow shared with to move the data between folders
            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(Const.LogicalOperator.OR, container, CRUD.MOVE, CRUD.UPDATE, CRUD.CREATE), container.getGUID());
            try {
                // labels are authenticated by the GCM tag: set them BEFORE sealing (META-ENCRYPTED-DATA §2.2)
                EncryptedData record = new EncryptedData();
                Object clear = nvb.getValue();
                record.setDataType(clear.getClass().getName());
                if (masked) {
                    record.setMask(computeMask(clear));
                }
                return CryptoUtil.encryptData(record, dataKey, BytesValueFilter.SINGLETON.validate(nvb));

            } catch (InvalidKeyException | NullPointerException
                     | IllegalArgumentException | NoSuchAlgorithmException
                     | NoSuchPaddingException
                     | InvalidAlgorithmParameterException
                     | IllegalBlockSizeException | BadPaddingException e) {
                // TODO Auto-generated catch block
                throw new AccessSecurityException(e.getMessage());
            }
        } else {
            return nvb.getValue();
        }
    }

    /**
     * The display fragment stored (and authenticated) in an {@code ENCRYPT_MASK} record: the last
     * four characters of the clear text preceded by {@code ****}, or {@code ****} alone when the value
     * is shorter than eight characters. Overridable for other masking policies.
     */
    protected String computeMask(Object clear) {
        String s = String.valueOf(clear);
        return s.length() >= 8 ? "****" + s.substring(s.length() - 4) : "****";
    }

    @SuppressWarnings("unchecked")
    @Override
    public final NVEntity decryptValues(APIDataStore<?, ?> dataStore, NVEntity container, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {

        if (container == null) {
            return null;
        }

        SUS.checkIfNulls("Null parameters", container.getGUID());
        // a sealed value is a packed record (byte[]), which a pair cannot hold: the store opens it on read
        for (NVBase<?> nvb : container.getAttributes().values().toArray(new NVBase[0])) {
            if (nvb instanceof NVEntityReference) {
                NVEntity temp = (NVEntity) nvb.getValue();
                if (temp != null) {
                    decryptValues(dataStore, temp, null);
                }
            } else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap) {
                ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
                for (NVEntity nve : arrayValues.values()) {
                    if (nve != null) {
                        decryptValues(dataStore, nve, null);
                    }
                }
            }
        }


        return container;

    }

    @Override
    public final String decryptValue(APIDataStore<?, ?> dataStore, NVEntity container, byte[] value, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {

        if (value == null) {
            return null;
        }

        SUS.checkIfNulls("Null parameters", container.getGUID());

        // the storage form is the packed record (META-ENCRYPTED-DATA §5); anything else is refused here
        EncryptedData ed = CipherCodecs.EDDecoder.decode(value);

        byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getGUID());
        try {
            return SUS.toString(CryptoUtil.decryptEncryptedData(ed, dataKey));

        } catch (NullPointerException
                 | IllegalArgumentException | InvalidKeyException |
                 NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | SignatureException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }


    @Override
    public final Object decryptValue(APIDataStore<?, ?> dataStore, NVEntity container, NVBase<?> nvb, Object value, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {

        if (container instanceof EncryptedData && !(container instanceof EncapsulatedKey)) {
            container.setValue(nvb.getName(), value);
            return nvb.getValue();
        }


        SUS.checkIfNulls("Null parameters", container.getGUID(), nvb);
        NVConfig nvc = ((NVConfigEntity) container.getNVConfig()).lookup(nvb.getName());

        if (value instanceof EncryptedData && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK))) {

            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getGUID());
            try {

                byte[] data = CryptoUtil.decryptEncryptedData((EncryptedData) value, dataKey);

                BytesValueFilter.setByteArrayToNVBase(nvb, data);


                return nvb.getValue();


            } catch (NullPointerException
                     | IllegalArgumentException | InvalidKeyException
                     | NoSuchAlgorithmException | NoSuchPaddingException
                     | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                     SignatureException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                throw new AccessSecurityException(e.getMessage());
            }
        } else {

            return value;
        }
    }

    @Override
    public final Object decryptValue(String userID, APIDataStore<?, ?> dataStore, NVEntity container, Object value, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {

        if (container instanceof EncryptedData && !(container instanceof EncapsulatedKey)) {
            return value;
        }


        SUS.checkIfNulls("Null parameters", container.getGUID());

        if (value instanceof EncryptedData) {
            //if(log.isEnabled()) log.getLogger().info("userID:" + userID);

            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, (userID != null ? userID : checkNVEntityAccess(container, CRUD.READ)), container.getGUID());
            try {

                byte[] data = CryptoUtil.decryptEncryptedData((EncryptedData) value, dataKey);
                return BytesValueFilter.bytesToValue(String.class, data);


            } catch (NullPointerException
                     | IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException |
                     NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                     BadPaddingException | SignatureException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                throw new AccessSecurityException(e.getMessage());
            }
        } else {

            return value;
        }
    }

    @Override
    public void associateNVEntityToSubjectGUID(NVEntity nve, String subjectGUID) {

        if (nve.getGUID() == null) {
            if (nve.getSubjectGUID() == null) {
                if (subjectGUID == null)
                    subjectGUID = currentSubjectGUID();

                /// must create a exclusion filter
                if (!(nve instanceof SubjectIdentifier || nve instanceof MessageTemplate))
                    nve.setSubjectGUID(subjectGUID);// != null ? subjectGUID : currentSubjectGUID());

                for (NVBase<?> nvb : nve.getAttributes().values().toArray(new NVBase[0])) {
                    if (nvb instanceof NVEntityReference) {
                        NVEntity temp = (NVEntity) nvb.getValue();
                        if (temp != null) {
                            associateNVEntityToSubjectGUID(temp, subjectGUID);
                        }
                    } else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap) {
                        @SuppressWarnings("unchecked")
                        ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
                        for (NVEntity nveTemp : arrayValues.values()) {
                            if (nveTemp != null) {
                                associateNVEntityToSubjectGUID(nveTemp, subjectGUID);
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public String currentSubjectID() throws AccessSecurityException {
        try {
            Object principal = SecurityUtils.getSubject().getPrincipal();
            return principal != null ? principal.toString() : null;
        } catch (org.apache.shiro.ShiroException | NullPointerException e) {
            return null; // no security manager / no subject bound on this thread
        }
    }

    /** GUID of the bound subject, null when nobody is bound or the principals carry no UUID. */
    @Override
    public String currentSubjectGUID() throws AccessSecurityException {
        try {
            PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
            UUID subjectGUID = principals != null ? principals.oneByType(UUID.class) : null;
            return subjectGUID != null ? subjectGUID.toString() : null;
        } catch (org.apache.shiro.ShiroException | NullPointerException e) {
            return null;
        }
    }


    public final boolean isNVEntityAccessible(NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException {
        return isNVEntityAccessible(Const.LogicalOperator.AND, nve, permissions);
    }


    public final boolean isNVEntityAccessible(Const.LogicalOperator lo, NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException {
        try {
            checkNVEntityAccess(lo, nve, permissions);
            return true;
        } catch (AccessSecurityException e) {
            //e.printStackTrace();
            return false;
        }
    }


    public final String checkNVEntityAccess(NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {
        return checkNVEntityAccess(Const.LogicalOperator.AND, nve, permissions);
    }


    /**
     * Resource access is a permission (user decision 2026-09-29), never a {@code subject_guid}
     * equality test: each requested verb is checked with
     * {@link ShiroUtil#checkResourcePermission(NVEntity, String)} — the owner passes through its
     * implicit {@code resource:<owner>:<owner>:read,update,delete,share}, a grantee through
     * {@code resource:<guid>:<grantee>:<verb>}. {@code OR} succeeds on the first verb held,
     * {@code AND} needs every verb. No verb ⇒ denied.
     *
     * @return the owner's subject GUID — the root of the resource's key chain
     * @throws AccessSecurityException when denied, unauthenticated, or the entity has no subject GUID
     */
    public final String checkNVEntityAccess(Const.LogicalOperator lo, NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {
        SUS.checkIfNulls("Null NVEntity", lo, nve);

        if (nve instanceof APICredentialsDAO || nve instanceof APITokenDAO) {
            return nve.getSubjectGUID();
        }
        if (nve.getGUID() == null || nve.getSubjectGUID() == null) {
            throw new AccessSecurityException("Resource without guid or subject_guid: " + nve.getClass().getName(), Reason.UNAUTHORIZED);
        }
        if (permissions == null || permissions.length == 0) {
            throw new AccessSecurityException("No permission requested for resource:" + nve.getGUID(), Reason.UNAUTHORIZED);
        }

        AccessSecurityException denied = null;
        for (CRUD permission : permissions) {
            try {
                ShiroUtil.checkResourcePermission(nve, verb(permission));
                if (lo == Const.LogicalOperator.OR) {
                    return nve.getSubjectGUID();
                }
            } catch (AccessSecurityException e) {
                if (lo == Const.LogicalOperator.AND) {
                    throw e;
                }
                denied = e;
            }
        }
        if (lo == Const.LogicalOperator.OR) {
            if (log.isEnabled())
                log.getLogger().info("denied resource:" + nve.getGUID() + " owner:" + nve.getSubjectGUID());
            throw denied != null ? denied
                    : new AccessSecurityException("Access Denied. for resource:" + nve.getGUID(), Reason.UNAUTHORIZED);
        }
        return nve.getSubjectGUID();
    }

    /** The verb part of a resource token for a CRUD value: {@code read}, {@code update}, ... */
    private static String verb(CRUD crud) {
        return crud.name().toLowerCase();
    }

    /**
     * {@inheritDoc}
     * <p>All requested verbs must be held ({@code AND}); evaluated with
     * {@link ShiroUtil#isResourcePermitted(String, String, String)} against the bound subject, so the
     * owner passes via its implicit self permission and a grantee via its grant. False when nobody
     * is bound, an id is null, or no verb is requested. Never throws.
     */
    @Override
    public final boolean isNVEntityAccessible(String nveRefID, String nveUserID, CRUD... permissions) {
        if (nveRefID == null || nveUserID == null || permissions == null || permissions.length == 0) {
            return false;
        }
        for (CRUD permission : permissions) {
            if (!ShiroUtil.isResourcePermitted(nveRefID, nveUserID, verb(permission))) {
                return false;
            }
        }
        return true;
    }
}
