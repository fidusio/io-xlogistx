package io.xlogistx.shiro;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.db.QueryMarker;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.CRUD;
import org.zoxweb.shared.util.GetValue;
import org.zoxweb.shared.util.SubjectID;

import java.security.NoSuchAlgorithmException;
import java.util.*;

public class XlogistXRealmManager
implements ShiroRealmStore
{
    public enum KeyType
    {
        SUBJECT,
        USER,
        PASSWORD
    }


    private final Map<String, Object> cacheMap = new LinkedHashMap<>();

    public static final LogWrapper log = new LogWrapper(XlogistXRealmManager.class).setEnabled(false);

    /**
     * Add a subject
     *
     * @param subject
     * @return ShiroSubject
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubject addSubject(ShiroSubject subject) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.CREATE, subject);
    }


    /**
     * Add a subject
     *
     * @param subject
     * @return ShiroSubject
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public SubjectIDDAO addSubject(SubjectIDDAO subject) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.CREATE, subject);
    }

    /**
     * Delete a subject
     *
     * @param subject
     * @param withRoles
     * @return ShiroSubject
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubject deleteSubject(ShiroSubject subject, boolean withRoles) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.DELETE, subject);
    }

    /**
     * Updates a subject, usually the password.
     *
     * @param subject
     * @return ShiroSubject
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubject updateSubject(ShiroSubject subject) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.UPDATE, subject);
    }

    /**
     * Add a role
     *
     * @param role
     * @return ShiroRoleDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRole addRole(ShiroRole role) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Lookup for a role based on the role ID which can either be ref_id or the role subject id
     *
     * @param roleID
     * @return the matching role or null if not found
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRole lookupRole(String roleID) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a role.
     *
     * @param role
     * @param withPermissions
     * @return ShiroRole
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRole deleteRole(ShiroRole role, boolean withPermissions) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Updates a role
     *
     * @param role
     * @return ShiroRole
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRole updateRole(ShiroRole role) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Adds a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroup
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroup addRoleGroup(ShiroRoleGroup rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroup
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroup deleteRoleGroup(ShiroRoleGroup rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Update a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroup
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroup updateRoleGroup(ShiroRoleGroup rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Add a permission
     *
     * @param permission
     * @return ShiroPermission
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermission addPermission(ShiroPermission permission) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Lookup permission based on the permission permission ID which can either be ref_id or the permission subject id
     *
     * @param permissionID
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermission lookupPermission(String permissionID) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a permission
     *
     * @param permission
     * @return ShiroPermission
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermission deletePermission(ShiroPermission permission) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Updates a permission.
     *
     * @param permission
     * @return ShiroPermission
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermission updatePermission(ShiroPermission permission) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Returns all subjects.
     *
     * @return list of ShiroSubject
     * @throws AccessException
     */
    @Override
    public List<ShiroSubject> getAllShiroSubjects() throws AccessException {
        return null;
    }

    /**
     * Returns all roles.
     *
     * @return list ShiroRole
     * @throws AccessException
     */
    @Override
    public List<ShiroRole> getAllShiroRoles() throws AccessException {
        return null;
    }

    /**
     * Returns all roles groups.
     *
     * @return list ShiroRoleGroup
     * @throws AccessException
     */
    @Override
    public List<ShiroRoleGroup> getAllShiroRoleGroups() throws AccessException {
        return null;
    }

    /**
     * Returns all permissions.
     *
     * @return list ShiroPermission
     * @throws AccessException
     */
    @Override
    public List<ShiroPermission> getAllShiroPermissions() throws AccessException {
        return null;
    }

    /**
     * Looks up a subject based on username.
     *
     * @param userName
     * @return ShiroSubject
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubject lookupSubject(String userName) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Looks up association collection.
     *
     * @param shiroDao
     * @param sat
     * @return ShiroCollectionAssociationDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
//    @Override
//    public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroBase shiroDao, ShiroAssociationType sat) throws NullPointerException, IllegalArgumentException, AccessException {
//        return null;
//    }

    /**
     * Create an association.
     *
     * @param association
     * @return ShiroAssociationDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroAssociationDAO addShiroAssociation(ShiroAssociationDAO association) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Removes an association.
     *
     * @param association
     * @return ShiroAssociationDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroAssociationDAO removeShiroAssociation(ShiroAssociationDAO association) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Get the user password
     *
     * @param domainID
     * @param userID
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public PasswordDAO getSubjectPassword(String domainID, String userID) throws NullPointerException, IllegalArgumentException, AccessException {
        return cacheGet(KeyType.PASSWORD, userID);
    }

    @Override
    public PasswordDAO setSubjectPassword(SubjectIDDAO subject, PasswordDAO passwd) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    @Override
    public PasswordDAO setSubjectPassword(String subject, PasswordDAO passwd) throws NullPointerException, IllegalArgumentException, AccessException {
        return cachePut(KeyType.PASSWORD, subject, passwd);
    }

    @Override
    public PasswordDAO setSubjectPassword(SubjectIDDAO subject, String passwd) throws NullPointerException, IllegalArgumentException, AccessException {
        PasswordDAO passwordDAO = null;
        try
        {
            //passwordDAO = HashUtil.toPassword(CryptoConst.HASHType.SHA_512, 0, 8196, passwd);
            passwordDAO = HashUtil.toPassword(CryptoConst.HASHType.BCRYPT, 0, 10, passwd);
            setSubjectPassword(subject.getSubjectID(), passwordDAO);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return passwordDAO;
    }

    @Override
    public PasswordDAO setSubjectPassword(String subject, String passwd) throws NullPointerException, IllegalArgumentException, AccessException {
        PasswordDAO passwordDAO = null;
        try
        {
            //passwordDAO = HashUtil.toPassword(CryptoConst.HASHType.SHA_512, 0, 8196, passwd);
            passwordDAO = HashUtil.toPassword(CryptoConst.HASHType.BCRYPT, 0, 10, passwd);
            setSubjectPassword(subject, passwordDAO);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return passwordDAO;
    }

    /**
     * Get the user roles
     *
     * @param domainID
     * @param userID
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public Set<String> getSubjectRoles(String domainID, String userID) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Get subject permissions
     *
     * @param domainID
     * @param userID
     * @param roleNames
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public Set<String> getSubjectPermissions(String domainID, String userID, Set<String> roleNames) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * @param subjectID
     * @param params
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public UserIDDAO lookupUserID(GetValue<String> subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * @param subjectID
     * @param params
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public UserIDDAO lookupUserID(String subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * @param subjectID
     * @param params
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public SubjectIDDAO lookupSubjectID(GetValue<String> subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {


        return null;
    }

    /**
     * @param subjectID
     * @param params
     * @return
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public SubjectIDDAO lookupSubjectID(String subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
        return (SubjectIDDAO) cacheGet(KeyType.SUBJECT, subjectID);
    }

    @Override
    public void addShiroRule(ShiroAssociationRuleDAO sard) {

    }

    @Override
    public void deleteShiroRule(ShiroAssociationRuleDAO sard) {

    }

    @Override
    public void updateShiroRule(ShiroAssociationRuleDAO sard) {

    }

    @Override
    public List<ShiroAssociationRuleDAO> search(QueryMarker... queryCriteria) {
        return null;
    }

    @Override
    public List<ShiroAssociationRuleDAO> search(Collection<QueryMarker> queryCriteria) {
        return null;
    }


    protected <T> T crudSubject(CRUD crud, SubjectID<String> subject)
    {
        synchronized (this) {
            switch (crud) {

                case UPDATE:
                case CREATE:
                    cachePut(KeyType.SUBJECT, subject.getSubjectID(), subject);
                    return (T) subject;
                case READ:
                    break;
                case DELETE:
                    return (T) cacheRemove(KeyType.SUBJECT, subject.getSubjectID());
                case MOVE:
                    break;
                case SHARE:
                    break;
                case EXEC:
                    break;
            }
        }
        throw new IllegalArgumentException("Unsupported operation:" + crud);
    }


    private <V> V cachePut(KeyType kt, String id, V value)
    {
        cacheMap.put(toKey(kt, id), value);
        return value;
    }

    private <V> V cacheGet(KeyType kt, String id)
    {
        return (V)cacheMap.get(toKey(kt,id));
    }

    private <V> V cacheRemove(KeyType kt, String id)
    {
        return (V)cacheMap.remove(toKey(kt,id));
    }




    private static String toKey(KeyType kt, String id)
    {
        return new StringBuilder().append(kt.name()).append("::").append(id).toString().toLowerCase();
    }
}
