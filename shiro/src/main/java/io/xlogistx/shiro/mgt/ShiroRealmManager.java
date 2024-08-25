package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.db.QueryMatchString;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.BaseSubjectID;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.MetaToken;
import org.zoxweb.shared.util.NotFoundException;

import java.util.Set;
import java.util.UUID;

public class ShiroRealmManager
implements ShiroRealmController<AuthorizationInfo, PrincipalCollection>
{

    private volatile APIDataStore<?> dataStore;
    /**
     * Create a subject identifier
     * @param subjectID the email or uuid identifier of the subject
     * @param subjectType the type of the subject
     * @return the created subject identifier
     * @throws AccessSecurityException if not permitted
     */
    public SubjectIdentifier addSubjectIdentifier(String subjectID, BaseSubjectID.SubjectType subjectType) throws AccessSecurityException {
        // 1 check if the subject exist
        //   yes throw exception
        // 2 no subject do not exist
        // 3 create subject identifier
        // 4 set GUID and subjectGUID to the same value
        // 5 use dataStore to persist subject

        SubjectIdentifier toCreate = lookupSubjectIdentifier(subjectID);

        if (toCreate != null)
            throw new AccessSecurityException(subjectID + " Already exists.");

        toCreate = new SubjectIdentifier();
        toCreate.setSubjectID(subjectID);
        toCreate.setGUID(UUID.randomUUID().toString());
        toCreate = getDataStore().insert(toCreate);
        return toCreate;
    }

    /**
     * Create a subject identifier
     *
     * @param subjectIdentifier the subject identifier
     * @return the created subject identifier
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public SubjectIdentifier addSubjectIdentifier(SubjectIdentifier subjectIdentifier) throws AccessSecurityException {
        // 1 check if the subject exist
        //   yes throw exception
        // 2 no subject do not exist
        // 3 create subject identifier
        // 4 set GUID and subjectGUID to the same value
        // 5 use dataStore to persist subject

        SubjectIdentifier toInsert = lookupSubjectIdentifier(subjectIdentifier.getSubjectID());

        if (toInsert != null)
            throw new AccessSecurityException(subjectIdentifier.getSubjectID() + " Already exists.");

        toInsert = subjectIdentifier;
        toInsert.setGUID(UUID.randomUUID().toString());
        toInsert = getDataStore().insert(toInsert);
        return toInsert;
    }

    /**
     * Delete a user identifier use with extreme care
     *
     * @param subjectID to be deleted
     * @return the deleted subject identifier
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public SubjectIdentifier deleteSubjectIdentifier(String subjectID) throws AccessSecurityException {
        ShiroUtil.checkPermissions(SecurityModel.toSecTok(SecurityModel.PERM_DELETE_USER, subjectID));
        SubjectIdentifier ret = lookupSubjectIdentifier(subjectID);
        if(ret != null)
            getDataStore().delete(ret, false);
        return ret;
    }

    /**
     * Lookup the he subject identifier based on its id
     * @param subjectID to look for
     * @return the matching subject identifier, null if not found
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public SubjectIdentifier lookupSubjectIdentifier(String subjectID)
    {
        return getDataStore().findOne(SubjectIdentifier.NVC_SUBJECT_IDENTIFIER, null, new QueryMatchString(MetaToken.SUBJECT_ID, subjectID, Const.RelationalOperator.EQUAL));
    }

    /**
     * Lookup subject credential info
     *
     * @param subjectID      the subject identifier
     * @param credentialType the
     * @return the subject credential
     */
    @Override
    public <C> C lookupCredential(String subjectID, CredentialInfo.CredentialType credentialType)
    {
        SubjectIdentifier subjectIdentifier = lookupSubjectIdentifier(subjectID);
        // if subject is null
        if(subjectIdentifier == null)
            throw new NotFoundException( subjectID + " do not exit");
        CredentialInfo ret = null;
        switch (credentialType)
        {
            case PASSWORD:
               ret = getDataStore().findOne(PasswordDAO.NVCE_PASSWORD_DAO,
                       null,
                       QueryMatchString.toQueryMatch(MetaToken.SUBJECT_GUID.getName() + "=" + subjectIdentifier.getSubjectGUID()),
                       QueryMatchString.toQueryMatch(MetaToken.GUID.getName() + "=" + subjectIdentifier.getGUID()));
                break;
            case PUBLIC_KEY:
                break;
            case SYMMETRIC_KEY:
                break;
            case API_KEY:
                break;
            case TOKEN:
                break;
        }

        return (C)ret;
    }

    /**
     * Add a credential object for the specified subject
     *
     * @param subjectID than owns the credentials
     * @param ci        the credential info object ie: password, public key, token ...
     * @return the validated credential info object
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public CredentialInfo addCredentialInfo(String subjectID, CredentialInfo ci) throws AccessSecurityException {

        SubjectIdentifier subjectIdentifier = lookupSubjectIdentifier(subjectID);
        // if subject is null
        if(subjectIdentifier == null)
            throw new NotFoundException( subjectID + " do not exit");
        if(ci instanceof  PasswordDAO)
        {
            PasswordDAO password = (PasswordDAO) ci;
            password.setGUID(subjectIdentifier.getGUID());
            password.setSubjectGUID(subjectIdentifier.getSubjectGUID());
            return getDataStore().insert(password);
        }

        // TODO support the rest of credential info
        throw new AccessSecurityException("Unsupported credential info " + (ci != null ? ci.getClass() : "."));
    }

    /**
     * Add a credential object for the specified subject
     *
     * @param subjectID than owns the credentials
     * @param password  the credential info object ie: password, public key, token ...
     * @return the validated credential info object
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public CredentialInfo addCredentialInfo(String subjectID, String password) throws AccessSecurityException {
        return null;
    }

    /**
     * Add a credential object for the specified subject
     *
     * @param subjectID than owns the credentials
     * @param password  the credential info object ie: password, public key, token ...
     * @return the validated credential info object
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public CredentialInfo addCredentialInfo(String subjectID, byte[] password) throws AccessSecurityException {
        return null;
    }

    /**
     * Delete a credential info
     *
     * @param ci to be deleted
     * @return the deleted credential info
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public CredentialInfo deleteCredentialInfo(CredentialInfo ci) throws AccessSecurityException {
        return null;
    }

    @Override
    public CredentialInfo updateCredentialInfo(CredentialInfo oldCI, CredentialInfo newCI) throws AccessSecurityException {
        return null;
    }

    /**
     * Add a shiro permission
     *
     * @param permission to be added
     * @return the added permission
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroPermission addPermission(ShiroPermission permission) throws AccessSecurityException {
        ShiroUtil.checkPermissions(SecurityModel.toSecTok(SecurityModel.PERM_ADD_PERMISSION, permission.getDomainAppID()));
        // validate if the pattern
        return null;
    }

    /**
     * Updated a shiro permission
     *
     * @param permission to be updated
     * @return the shiro permission
     * @throws AccessSecurityException if no permitted
     */
    @Override
    public ShiroPermission updatePermission(ShiroPermission permission) throws AccessSecurityException {
        return null;
    }

    /**
     * Delete a shiro permission
     *
     * @param permission to be deleted
     * @return the deleted permission null if not found
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroPermission deletePermission(ShiroPermission permission) throws AccessSecurityException {
        return null;
    }

    /**
     * Add a shiro role
     *
     * @param shiroRole to be added
     * @return the added shiro role
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRole addRole(ShiroRole shiroRole) throws AccessSecurityException {
        return null;
    }

    /**
     * Update a shiro role
     *
     * @param shiroRole to be added
     * @return the added shiro role
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRole updateRole(ShiroRole shiroRole) throws AccessSecurityException {
        return null;
    }

    /**
     * Delete a shiro role
     *
     * @param shiroRole to be deleted
     * @return the deleted shiro role
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRole deleteRole(ShiroRole shiroRole) throws AccessSecurityException {
        return null;
    }

    /**
     * Add a shiro group role
     *
     * @param shiroRoleGroup to be added
     * @return the added shiro role group
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRoleGroup addRoleGroup(ShiroRoleGroup shiroRoleGroup) throws AccessSecurityException {
        return null;
    }

    /**
     * Update a shiro group role
     *
     * @param shiroRoleGroup to be updated
     * @return the updated shiro role group
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRoleGroup updateRoleGroup(ShiroRoleGroup shiroRoleGroup) throws AccessSecurityException {
        return null;
    }

    /**
     * Delete a shiro group role
     *
     * @param shiroRoleGroup to be deleted
     * @return the deleted shiro role group
     * @throws AccessSecurityException if not permitted
     */
    @Override
    public ShiroRoleGroup deleteRoleGroup(ShiroRoleGroup shiroRoleGroup) throws AccessSecurityException {
        return null;
    }

    /**
     * Add a shiro authorization info
     *
     * @param shiroAuthzInfo to added
     * @return the added shiro authorization info
     * @throws AccessSecurityException if no permitted
     */
    @Override
    public ShiroAuthzInfo addShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo) throws AccessSecurityException {
        return null;
    }

    @Override
    public Set<ShiroAuthzInfo> lookupSubjectAuthzInfo(String subjectIdentifier) throws AccessSecurityException {
        return null;
    }

    /**
     * Update a shiro authorization info
     *
     * @param shiroAuthzInfo to updated
     * @return the updated shiro authorization info
     * @throws AccessSecurityException if no permitted
     */
    @Override
    public ShiroAuthzInfo updateShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo) throws AccessSecurityException {
        return null;
    }

    /**
     * Delete a shiro authorization info
     *
     * @param shiroAuthzInfo to delted
     * @return the deleted shiro authorization info
     * @throws AccessSecurityException if no permitted
     */
    @Override
    public ShiroAuthzInfo deleteShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo) throws AccessSecurityException {
        return null;
    }

    @Override
    public AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection pc) {
        return null;
    }

    public APIDataStore<?> getDataStore()
    {
        if(dataStore == null)
            throw new NullPointerException("data store not set.");

        return dataStore;
    }

    public void setDataStore(APIDataStore<?> dataStore)
    {
        this.dataStore = dataStore;
    }
}
