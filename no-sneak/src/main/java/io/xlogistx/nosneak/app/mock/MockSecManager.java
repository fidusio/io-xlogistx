package io.xlogistx.nosneak.app.mock;

import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.security.*;

public class MockSecManager implements SubjectSecurityManager {
    @Override
    public void login(String subjectID, String credential) throws SecurityException {
        throw new SecurityException("Invalid credential for subject " + subjectID);
    }

    @Override
    public SubjectIdentifier createSubjectID(String principalID, CredentialInfo credentialInfo) {
        return null;
    }

    @Override
    public SubjectIdentifier lookupSubjectID(String principalID) {
        return null;
    }

    @Override
    public void updateSubjectID(SubjectIdentifier update) {

    }

    @Override
    public boolean deleteSubjectID(SubjectIdentifier subject) {
        return false;
    }

    @Override
    public CredentialInfo createCredential(String principalID, CredentialInfo credential) {
        return null;
    }

    @Override
    public CredentialInfo lookupCredential(String principalID, CredentialInfo.Type type) {
        return null;
    }

    @Override
    public void updateCredential(CredentialInfo update) {

    }

    @Override
    public void deleteCredential(CredentialInfo credential) {

    }

    @Override
    public CredentialInfo[] lookupAllPrincipalCredentials(String principalID) {
        return new CredentialInfo[0];
    }

    @Override
    public PrincipalIdentifier addPrincipalID(SubjectIdentifier subject, String principalID) {
        return null;
    }

    @Override
    public PrincipalIdentifier lookupPrincipalID(String principalID) {
        return null;
    }

    @Override
    public boolean deletePrincipalID(PrincipalIdentifier principal) {
        return false;
    }

    @Override
    public PrincipalIdentifier[] lookupAllPrincipalIdentifiers(String subjectGUID) {
        return new PrincipalIdentifier[0];
    }

    @Override
    public PermissionInfo createPermission(PermissionInfo permission) {
        return null;
    }

    @Override
    public PermissionInfo lookupPermission(String appID, String permissionName) {
        return null;
    }

    @Override
    public PermissionInfo[] lookupAllPermissionsByAppID(String appID) {
        return new PermissionInfo[0];
    }

    @Override
    public void updatePermission(PermissionInfo update) {

    }

    @Override
    public boolean deletePermission(PermissionInfo permission) {
        return false;
    }

    @Override
    public PermissionInfo[] getPermissions() {
        return new PermissionInfo[0];
    }

    @Override
    public RoleInfo createRole(RoleInfo role) {
        return null;
    }

    @Override
    public RoleInfo lookupRole(String appID, String roleName) {
        return null;
    }

    @Override
    public RoleInfo[] lookupAllRolesByAppID(String appID) {
        return new RoleInfo[0];
    }

    @Override
    public void updateRole(RoleInfo update) {

    }

    @Override
    public boolean deleteRole(RoleInfo role) {
        return false;
    }

    @Override
    public RoleInfo[] getRoles() {
        return new RoleInfo[0];
    }

    @Override
    public RoleGroupInfo createRoleGroup(RoleGroupInfo roleGroup) {
        return null;
    }

    @Override
    public RoleGroupInfo lookupRoleGroup(String appID, String roleGroupName) {
        return null;
    }

    @Override
    public RoleGroupInfo[] lookupAllRoleGroupsByAppID(String appID) {
        return new RoleGroupInfo[0];
    }

    @Override
    public void updateRoleGroup(RoleGroupInfo update) {

    }

    @Override
    public boolean deleteRoleGroup(RoleGroupInfo roleGroup) {
        return false;
    }

    @Override
    public RoleGroupInfo[] getRoleGroups() {
        return new RoleGroupInfo[0];
    }

    @Override
    public PermissionGrant addPermissionGrant(SubjectIdentifier subject, PermissionInfo permissionInfo) {
        return null;
    }

    @Override
    public boolean deletePermissionGrant(PermissionGrant permissionGrant) {
        return false;
    }

    @Override
    public PermissionGrant[] getPermissionGrants(String subjectGUID) {
        return new PermissionGrant[0];
    }

    @Override
    public RoleGrant addRoleGrant(SubjectIdentifier subject, RoleInfo roleInfo) {
        return null;
    }

    @Override
    public boolean deleteRoleGrant(RoleGrant roleGrant) {
        return false;
    }

    @Override
    public RoleGrant[] getRoleGrants(String subjectGUID) {
        return new RoleGrant[0];
    }

    @Override
    public RoleGroupGrant addRoleGroupGrant(SubjectIdentifier subject, RoleGroupInfo roleGroupInfo) {
        return null;
    }

    @Override
    public boolean deleteRoleGroupGrant(RoleGroupGrant roleGroupGrant) {
        return false;
    }

    @Override
    public RoleGroupGrant[] getRoleGroupGrants(String subjectGUID) {
        return new RoleGroupGrant[0];
    }

    @Override
    public void setDataStore(APIDataStore<?, ?> dataStore) {

    }

    @Override
    public APIDataStore<?, ?> getDataStore() {
        return null;
    }
}
