package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.DomainPrincipalCollection;
import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.ds.DSAuthorizingRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CipherCodecs;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APICredentials;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APIToken;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.EncryptedData;
import org.zoxweb.shared.crypto.EncapsulatedKey;
import org.zoxweb.shared.data.MessageTemplate;
import org.zoxweb.shared.filters.BytesValueFilter;
import org.zoxweb.shared.filters.ChainedFilter;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.ExceptionReason.Reason;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The {@link SecurityController} of a store guarded by Shiro: field encryption under the owner's key
 * chain, the owner stamping of new rows and the access verdicts the datastore asks for.
 * <p>
 * <b>Dual ownership (user decision 2026-10-19/20).</b> A new row gets the bound subject in
 * {@code subject_guid} as before and, when the subject is logged into an app whose registered class
 * list ({@link AppIDDefault#getResourceTypes()}) holds the row's class, the app record's GUID in
 * {@code app_guid}: the app then owns the row. Its access check is the app-resource token
 * ({@link ShiroUtil#checkResourcePermission(String, String, String, String, String)}) and its key chain
 * is rooted at the app's owner subject, the registrar {@code registrar.<domain>-<app>}
 * ({@link #keyOwnerOf(APIDataStore, NVEntity)}); the creating subject keeps nothing by
 * {@code subject_guid} alone. A login without app, a class the app did not register, an entity that
 * arrives with a GUID or an owner: no app stamp, the row stays the subject's.
 */
public class ShiroSecurityController
        implements SecurityController {

    public static final LogWrapper log = new LogWrapper(ShiroSecurityController.class).setEnabled(false);

//    @Override
//    public void validateCredential(CredentialInfo ci, String input) throws AccessSecurityException {
//
//    }
//
//    @Override
//    public void validateCredential(CredentialInfo ci, byte[] input) throws AccessSecurityException {
//
//    }

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
            resourceAccessor(Const.LogicalOperator.OR, container, CRUD.MOVE, CRUD.UPDATE, CRUD.CREATE);
            byte[] dataKey = dataKey(dataStore, msKey, keyOwnerOf(dataStore, container), container.getGUID());
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

        resourceAccessor(container, CRUD.READ);
        byte[] dataKey = dataKey(dataStore, msKey, keyOwnerOf(dataStore, container), container.getGUID());
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

            resourceAccessor(container, CRUD.READ);
            byte[] dataKey = dataKey(dataStore, msKey, keyOwnerOf(dataStore, container), container.getGUID());
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

            String root;
            if (userID != null) {
                root = userID;
            } else {
                resourceAccessor(container, CRUD.READ);
                root = keyOwnerOf(dataStore, container);
            }
            byte[] dataKey = dataKey(dataStore, msKey, root, container.getGUID());
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

    /**
     * The entity's data key, read through the owner's key chain in the system context: the caller
     * has already passed the access check on the entity, and the key rows it walks belong to the
     * owner — a grantee may not read them through the store on its own.
     */
    private byte[] dataKey(APIDataStore<?, ?> dataStore, byte[] msKey, String ownerGUID, String entityGUID) {
        return runAsSystem(() -> KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, ownerGUID, entityGUID));
    }

    /**
     * The root of an entity's key chain (dual ownership, user decision 2026-10-20): the
     * {@code subject_guid} of the app record named by {@code app_guid} when set — the app's owner
     * subject, its registrar, whose subject key wraps the entity key — else the row's own
     * {@code subject_guid}. The app record is read in the system context: the caller has already
     * passed the access check on the entity. The app record itself is its own app ({@code app_guid}
     * = {@code guid}) and is rooted at its owner directly.
     *
     * @throws AccessSecurityException when the app record does not exist or has no owner subject
     */
    public static String keyOwnerOf(APIDataStore<?, ?> dataStore, NVEntity nve) {
        SUS.checkIfNulls("Null NVEntity", nve);
        String appGUID = nve.getAppGUID();
        if (SUS.isEmpty(appGUID) || nve instanceof AppIDDefault) {
            return nve.getSubjectGUID();
        }
        SUS.checkIfNulls("a datastore is required to resolve the app owning " + nve.getGUID(), dataStore);
        AppIDDefault app = ShiroUtil.runAsSystem(() -> {
            List<AppIDDefault> rows = dataStore.searchByID(AppIDDefault.NVC_APP_ID_DEFAULT, appGUID);
            return rows == null || rows.isEmpty() ? null : rows.get(0);
        });
        if (app == null) {
            throw new AccessSecurityException("unknown app " + appGUID + " owning resource " + nve.getGUID(), Reason.UNAUTHORIZED);
        }
        if (SUS.isEmpty(app.getSubjectGUID())) {
            throw new AccessSecurityException("app " + appGUID + " has no owner subject: no key chain for resource " + nve.getGUID(), Reason.UNAUTHORIZED);
        }
        return app.getSubjectGUID();
    }

    /** {@inheritDoc} Delegates to {@link ShiroUtil#runAsSystem(Supplier)}. */
    @Override
    public <V> V runAsSystem(Supplier<V> work) {
        return ShiroUtil.runAsSystem(work);
    }

    @Override
    public boolean isSystemContext() {
        return ShiroUtil.isSystemContext();
    }

    /**
     * {@inheritDoc}
     * <p>Owner stamping of a new entity (no GUID, no {@code subject_guid}): {@code subject_guid} =
     * the given subject or the bound one, and — when the bound subject is logged into an app whose
     * registered class list holds the entity's class ({@link SecurityModel#resourceTypeOf(NVEntity)})
     * — {@code app_guid} = that app record's GUID: the app owns the row (dual ownership, 2026-10-20).
     * Children in the recursion decide by their own class. {@link SubjectIdentifier},
     * {@link MessageTemplate} and {@link AppIDDefault} are never stamped. An entity arriving with a
     * GUID or an owner is left as it is. The app's class list is read at every call, so a
     * registration takes effect without a new login.
     */
    @Override
    public void associateResourceToSubject(NVEntity nve, String subjectGUID) {
        if (nve == null) {
            return;
        }
        associate(nve, subjectGUID, nve.getGUID() == null && nve.getSubjectGUID() == null ? currentApp() : null);
    }

    private void associate(NVEntity nve, String subjectGUID, AppIDDefault app) {

        if (nve.getGUID() == null) {
            if (nve.getSubjectGUID() == null) {
                if (subjectGUID == null)
                    subjectGUID = currentSubjectGUID();

                /// must create a exclusion filter
                if (!isStampingExcluded(nve)) {
                    nve.setSubjectGUID(subjectGUID);// != null ? subjectGUID : currentSubjectGUID());
                    if (app != null && nve.getAppGUID() == null && app.isResourceTypeRegistered(SecurityModel.resourceTypeOf(nve))) {
                        nve.setAppGUID(app.getGUID()); // the app owns the row: its class is registered on the login's app
                    }
                }

                for (NVBase<?> nvb : nve.getAttributes().values().toArray(new NVBase[0])) {
                    if (nvb instanceof NVEntityReference) {
                        NVEntity temp = (NVEntity) nvb.getValue();
                        if (temp != null) {
                            associate(temp, subjectGUID, app);
                        }
                    } else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap) {
                        @SuppressWarnings("unchecked")
                        ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
                        for (NVEntity nveTemp : arrayValues.values()) {
                            if (nveTemp != null) {
                                associate(nveTemp, subjectGUID, app);
                            }
                        }
                    }
                }
            }
        }
    }

    /** Entities that never receive an owner stamp: subjects, message templates and app records. */
    private static boolean isStampingExcluded(NVEntity nve) {
        return nve instanceof SubjectIdentifier || nve instanceof MessageTemplate || nve instanceof AppIDDefault;
    }

    @Override
    public String currentPrincipalID() throws AccessSecurityException {
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

    /**
     * {@inheritDoc}
     * <p>The app record GUID the realm resolved at login ({@link ShiroUtil#subjectAppGUID()}); null for
     * a login without app, when nobody is bound (setup runs with nobody bound) or without a security manager.
     */
    @Override
    public String currentAppGUID() {
        try {
            return ShiroUtil.subjectAppGUID();
        } catch (org.apache.shiro.ShiroException | AccessSecurityException | NullPointerException e) {
            return null;
        }
    }

    /**
     * The stored record of the app the bound subject logged into, read through the realm's security
     * manager in the system context, or null for a login without app, an app without record, nobody
     * bound, or no datastore realm. Read at every call: the registered class list is live.
     */
    protected AppIDDefault currentApp() {
        try {
            PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
            if (!(principals instanceof DomainPrincipalCollection)) {
                return null;
            }
            DomainPrincipalCollection dpc = (DomainPrincipalCollection) principals;
            if (SUS.isEmpty(dpc.getAppGUID()) || SUS.isEmpty(dpc.getDomainID()) || SUS.isEmpty(dpc.getAppID())) {
                return null;
            }
            DSAuthorizingRealm realm = ShiroUtil.getRealm(DSAuthorizingRealm.class);
            DomainSecurityManager dsm = realm != null ? realm.getDomainSecurityManager() : null;
            if (dsm == null) {
                return null;
            }
            AppIDDefault record = runAsSystem(() -> dsm.lookupApp(dpc.getDomainID(), dpc.getAppID()));
            // the record named by the login: a record replaced since the login does not own the new rows
            return record != null && dpc.getAppGUID().equalsIgnoreCase(record.getGUID()) ? record : null;
        } catch (org.apache.shiro.ShiroException | AccessSecurityException | NullPointerException | IllegalArgumentException e) {
            return null;
        }
    }


    public final boolean isResourceAccessible(NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException {
        return isResourceAccessible(Const.LogicalOperator.AND, nve, permissions);
    }


    public final boolean isResourceAccessible(Const.LogicalOperator lo, NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException {
        try {
            resourceAccessor(lo, nve, permissions);
            return true;
        } catch (AccessSecurityException e) {
            //e.printStackTrace();
            return false;
        }
    }


    public final String resourceAccessor(NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {
        return resourceAccessor(Const.LogicalOperator.AND, nve, permissions);
    }


    /**
     * Resource access is a permission (user decision 2026-09-29), never a {@code subject_guid}
     * equality test: each requested verb is checked with
     * {@link ShiroUtil#checkResourcePermission(NVEntity, String)} — the owner passes through its
     * implicit {@code resource:<owner>:<owner>:create,read,update,delete,share}, a grantee through
     * {@code resource:<guid>:<grantee>:<verb>}, and on a row an app owns ({@code app_guid} set) the
     * owner half is the app-resource token {@code app_resource:<app>:<class>:<caller>:<verb>}.
     * {@code OR} succeeds on the first verb held, {@code AND} needs every verb. No verb ⇒ denied.
     *
     * @return the resource's {@code subject_guid}: the owner of a row no app owns and the root of its
     * key chain; for an app-owned row only the creating subject — its chain is rooted at
     * {@link #keyOwnerOf(APIDataStore, NVEntity)}
     * @throws AccessSecurityException when denied, unauthenticated, or the entity has no subject GUID
     */
    public final String resourceAccessor(Const.LogicalOperator lo, NVEntity nve, CRUD... permissions)
            throws NullPointerException, IllegalArgumentException, AccessSecurityException {
        SUS.checkIfNulls("Null NVEntity", lo, nve);

        if (nve instanceof APICredentials || nve instanceof APIToken) {
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
                log.getLogger().info("denied resource:" + nve.getGUID() + " owner:" + nve.getSubjectGUID() + " app:" + nve.getAppGUID());
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
     * owner passes via its implicit self permission and a grantee via its grant. A null owner
     * ({@code nveUserID}) is a resource without owner: only a grant on the resource (or a wildcard)
     * reaches it. True in the system context. False when nobody is bound, the resource id is null,
     * or no verb is requested. Never throws.
     */
    @Override
    public final boolean isResourceAccessible(String nveRefID, String nveUserID, CRUD... permissions) {
        return isResourceAccessible(nveRefID, nveUserID, null, null, permissions);
    }

    /**
     * {@inheritDoc}
     * <p>The app-aware verdict: a row with {@code appGUID} and {@code resourceType} is judged on the
     * app-resource token, else on the owner token, then on a share
     * ({@link ShiroUtil#isResourcePermitted(String, String, String, String, String)}). All verbs
     * required. Never throws.
     */
    @Override
    public final boolean isResourceAccessible(String nveRefID, String nveUserID, String appGUID, String resourceType, CRUD... permissions) {
        if (nveRefID == null || permissions == null || permissions.length == 0) {
            return false;
        }
        for (CRUD permission : permissions) {
            if (!ShiroUtil.isResourcePermitted(nveRefID, nveUserID, appGUID, resourceType, verb(permission))) {
                return false;
            }
        }
        return true;
    }
}
