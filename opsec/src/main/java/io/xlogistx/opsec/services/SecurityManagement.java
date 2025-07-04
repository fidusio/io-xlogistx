package io.xlogistx.opsec.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.RealmController;

import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;

public class SecurityManagement
extends PropertyContainer
{

    @EndPointProp(methods = {HTTPMethod.POST}, name="create-subject", uris="/opsec/regsiter/subject")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = SecurityModel.PERM_ADD_USER)
    public SimpleMessage createSubject(@ParamProp(name="",source = Const.ParamSource.PAYLOAD) NVGenericMap subjectInfoCredentials)
    {
        RealmController realmManager = ShiroUtil.getRealmController();
        // get the subject info from the
        String subjectID = subjectInfoCredentials.lookup("subject_id");

        NVGenericMap credentials = subjectInfoCredentials.lookup("credentials");
        // credentials could be password
        // public key

        return null;
    }

    @EndPointProp(methods = {HTTPMethod.DELETE}, name="delete-subject", uris="/opsec/unregister/{$subject_id}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = SecurityModel.PERM_DELETE_SUBJECT)
    public SimpleMessage createSubject(@ParamProp( name = "subject_id") String subjectID)
    {
        RealmController realmManager = ShiroUtil.getRealmController();


        return null;
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="add-permission", uris="/opsec/add/permission")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = SecurityModel.PERM_ADD_PERMISSION)
    public SimpleMessage createPermission(@ParamProp(name="",source = Const.ParamSource.PAYLOAD) NVGenericMap permissionInfo)
    {
        RealmController realmManager = ShiroUtil.getRealmController();


        return null;
    }


    @Override
    protected void refreshProperties() {

    }
}
