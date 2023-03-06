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
     * @return ShiroSubjectDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubjectDAO addSubject(ShiroSubjectDAO subject) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.CREATE, subject);
    }


    /**
     * Add a subject
     *
     * @param subject
     * @return ShiroSubjectDAO
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
     * @return ShiroSubjectDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubjectDAO deleteSubject(ShiroSubjectDAO subject, boolean withRoles) throws NullPointerException, IllegalArgumentException, AccessException {
        return crudSubject(CRUD.DELETE, subject);
    }

    /**
     * Updates a subject, usually the password.
     *
     * @param subject
     * @return ShiroSubjectDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubjectDAO updateSubject(ShiroSubjectDAO subject) throws NullPointerException, IllegalArgumentException, AccessException {
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
    public ShiroRoleDAO addRole(ShiroRoleDAO role) throws NullPointerException, IllegalArgumentException, AccessException {
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
    public ShiroRoleDAO lookupRole(String roleID) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a role.
     *
     * @param role
     * @param withPermissions
     * @return ShiroRoleDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleDAO deleteRole(ShiroRoleDAO role, boolean withPermissions) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Updates a role
     *
     * @param role
     * @return ShiroRoleDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleDAO updateRole(ShiroRoleDAO role) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Adds a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroupDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroupDAO addRoleGroup(ShiroRoleGroupDAO rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroupDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroupDAO deleteRoleGroup(ShiroRoleGroupDAO rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Update a role group.
     *
     * @param rolegroup
     * @return ShiroRoleGroupDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroRoleGroupDAO updateRoleGroup(ShiroRoleGroupDAO rolegroup) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Add a permission
     *
     * @param permission
     * @return ShiroPermissionDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermissionDAO addPermission(ShiroPermissionDAO permission) throws NullPointerException, IllegalArgumentException, AccessException {
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
    public ShiroPermissionDAO lookupPermission(String permissionID) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Delete a permission
     *
     * @param permission
     * @return ShiroPermissionDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermissionDAO deletePermission(ShiroPermissionDAO permission) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Updates a permission.
     *
     * @param permission
     * @return ShiroPermissionDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroPermissionDAO updatePermission(ShiroPermissionDAO permission) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

    /**
     * Returns all subjects.
     *
     * @return list of ShiroSubjectDAO
     * @throws AccessException
     */
    @Override
    public List<ShiroSubjectDAO> getAllShiroSubjects() throws AccessException {
        return null;
    }

    /**
     * Returns all roles.
     *
     * @return list ShiroRoleDAO
     * @throws AccessException
     */
    @Override
    public List<ShiroRoleDAO> getAllShiroRoles() throws AccessException {
        return null;
    }

    /**
     * Returns all roles groups.
     *
     * @return list ShiroRoleGroupDAO
     * @throws AccessException
     */
    @Override
    public List<ShiroRoleGroupDAO> getAllShiroRoleGroups() throws AccessException {
        return null;
    }

    /**
     * Returns all permissions.
     *
     * @return list ShiroPermissionDAO
     * @throws AccessException
     */
    @Override
    public List<ShiroPermissionDAO> getAllShiroPermissions() throws AccessException {
        return null;
    }

    /**
     * Looks up a subject based on username.
     *
     * @param userName
     * @return ShiroSubjectDAO
     * @throws NullPointerException
     * @throws IllegalArgumentException
     * @throws AccessException
     */
    @Override
    public ShiroSubjectDAO lookupSubject(String userName) throws NullPointerException, IllegalArgumentException, AccessException {
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
    @Override
    public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroDAO shiroDao, ShiroAssociationType sat) throws NullPointerException, IllegalArgumentException, AccessException {
        return null;
    }

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
        return null;
    }

    @Override
    public PasswordDAO setSubjectPassword(SubjectIDDAO subject, String passwd) throws NullPointerException, IllegalArgumentException, AccessException {
        PasswordDAO passwordDAO = null;
        try
        {
            passwordDAO = HashUtil.toPassword(CryptoConst.AlgoType.SHA_512, 0, 8196, passwd);
            cachePut(KeyType.PASSWORD, subject.getSubjectID(), passwordDAO);

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
            passwordDAO = HashUtil.toPassword(CryptoConst.AlgoType.SHA_512, 0, 8196, passwd);
            cachePut(KeyType.PASSWORD, subject, passwordDAO);

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
