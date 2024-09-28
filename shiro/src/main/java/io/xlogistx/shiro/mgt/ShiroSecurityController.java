package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APICredentialsDAO;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.crypto.EncryptedData;
import org.zoxweb.shared.crypto.EncryptedKey;
import org.zoxweb.shared.data.MessageTemplateDAO;
import org.zoxweb.shared.filters.BytesValueFilter;
import org.zoxweb.shared.filters.ChainedFilter;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.UUID;

public class ShiroSecurityController
    implements SecurityController

{

    public static final LogWrapper log = new LogWrapper(ShiroSecurityController.class).setEnabled(false);
    @Override
    public void validateCredential(CredentialInfo ci, String input) throws AccessSecurityException {

    }

    @Override
    public void validateCredential(CredentialInfo ci, byte[] input) throws AccessSecurityException {

    }

    @Override
    public final Object encryptValue(APIDataStore<?> dataStore, NVEntity container, NVConfig nvc, NVBase<?> nvb, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessException
    {
        SharedUtil.checkIfNulls("Null parameters", container.getGUID(), nvb);



        boolean encrypt = false;

        // the nvpair filter will override nvc value
        if (nvb instanceof NVPair &&
                (ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT_MASK)))
        {
            encrypt = true;

        }
        else if (nvc != null && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
        {
            encrypt = true;
        }





        if (encrypt && nvb.getValue() != null)
        {
            // CRUD.MOVE was to allow shared with to move the data between folders
            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(Const.LogicalOperator.OR, container, CRUD.MOVE, CRUD.UPDATE, CRUD.CREATE), container.getGUID());
            try
            {
                return CryptoUtil.encryptData(new EncryptedData(), dataKey, BytesValueFilter.SINGLETON.validate(nvb));

            } catch (InvalidKeyException | NullPointerException
                     | IllegalArgumentException | NoSuchAlgorithmException
                     | NoSuchPaddingException
                     | InvalidAlgorithmParameterException
                     | IllegalBlockSizeException | BadPaddingException e)
            {
                // TODO Auto-generated catch block
                throw new AccessException(e.getMessage());
            }
        }
        else
        {
            return nvb.getValue();
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public final NVEntity decryptValues(APIDataStore<?> dataStore, NVEntity container, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessException
    {

        if (container == null)
        {
            return null;
        }

        SharedUtil.checkIfNulls("Null parameters", container.getGUID());
        for (NVBase<?> nvb : container.getAttributes().values().toArray( new NVBase[0]))
        {
            if (nvb instanceof NVPair)
            {
                decryptValue(dataStore, container, (NVPair)nvb, null);
            }
            else if (nvb instanceof NVEntityReference)
            {
                NVEntity temp = (NVEntity) nvb.getValue();
                if (temp != null)
                {
                    decryptValues(dataStore, temp, null);
                }
            }
            else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
            {
                ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
                for (NVEntity nve : arrayValues.values())
                {
                    if (nve != null)
                    {
                        decryptValues(dataStore, container, null);
                    }
                }
            }
        }


        return container;

    }

    @Override
    public final String decryptValue(APIDataStore<?> dataStore, NVEntity container, NVPair nvp, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessException
    {

        if (container instanceof EncryptedData)
        {
            return nvp != null ? nvp.getValue() : null;
        }


        SharedUtil.checkIfNulls("Null parameters", container.getGUID(), nvp);

        if (nvp.getValue()!= null && (ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT_MASK)))
        {

            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getGUID());
            try
            {
                EncryptedData ed = EncryptedData.fromCanonicalID(nvp.getValue());
                byte[] data = CryptoUtil.decryptEncryptedData(ed, dataKey);

                nvp.setValue(SharedStringUtil.toString(data));
                return nvp.getValue();


            } catch (NullPointerException
                     | IllegalArgumentException | InvalidKeyException |
                     NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                     IllegalBlockSizeException | BadPaddingException | SignatureException e)
            {
                // TODO Auto-generated catch block
                throw new AccessException(e.getMessage());
            }
        }
        else
        {
            return nvp.getValue();
        }
    }


    @Override
    public final Object decryptValue(APIDataStore<?> dataStore, NVEntity container, NVBase<?> nvb, Object value, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessException
    {

        if (container instanceof EncryptedData && !(container instanceof EncryptedKey))
        {
            container.setValue(nvb.getName(), value);
            return nvb.getValue();
        }


        SharedUtil.checkIfNulls("Null parameters", container.getGUID(), nvb);
        NVConfig nvc = ((NVConfigEntity)container.getNVConfig()).lookup(nvb.getName());

        if (value instanceof EncryptedData && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
        {

            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getGUID());
            try
            {

                byte[] data = CryptoUtil.decryptEncryptedData((EncryptedData) value, dataKey);

                BytesValueFilter.setByteArrayToNVBase(nvb, data);


                return nvb.getValue();


            } catch (NullPointerException
                     | IllegalArgumentException | InvalidKeyException
                     | NoSuchAlgorithmException | NoSuchPaddingException
                     | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
                throw new AccessException(e.getMessage());
            }
        }
        else
        {

            return value;
        }
    }

    @Override
    public final Object decryptValue(String userID, APIDataStore<?> dataStore, NVEntity container, Object value, byte[] msKey)
            throws NullPointerException, IllegalArgumentException, AccessException
    {

        if (container instanceof EncryptedData && !(container instanceof EncryptedKey))
        {
            return value;
        }


        SharedUtil.checkIfNulls("Null parameters", container.getGUID());

        if (value instanceof EncryptedData)
        {
            //if(log.isEnabled()) log.getLogger().info("userID:" + userID);

            byte[] dataKey = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, (userID != null ?  userID : checkNVEntityAccess(container, CRUD.READ)), container.getGUID());
            try
            {

                byte[] data = CryptoUtil.decryptEncryptedData((EncryptedData) value, dataKey);
                return BytesValueFilter.bytesToValue(String.class, data);


            } catch (NullPointerException
                     | IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
                throw new AccessException(e.getMessage());
            }
        }
        else
        {

            return value;
        }
    }

    @Override
    public void associateNVEntityToSubjectGUID(NVEntity nve, String subjectGUID)
    {

        if (nve.getGUID() == null)
        {
            if (nve.getSubjectGUID() == null)
            {
                if(subjectGUID == null)
                    subjectGUID = currentSubjectGUID();

                /// must create a exclusion filter
                if (!(nve instanceof SubjectIdentifier || nve instanceof MessageTemplateDAO))
                    nve.setSubjectGUID(subjectGUID);// != null ? subjectGUID : currentSubjectGUID());

                for (NVBase<?> nvb : nve.getAttributes().values().toArray(new NVBase[0]))
                {
                    if (nvb instanceof NVEntityReference)
                    {
                        NVEntity temp = (NVEntity) nvb.getValue();
                        if (temp != null)
                        {
                            associateNVEntityToSubjectGUID(temp, subjectGUID);
                        }
                    }
                    else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
                    {
                        @SuppressWarnings("unchecked")
                        ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
                        for (NVEntity nveTemp : arrayValues.values())
                        {
                            if (nveTemp != null)
                            {
                                associateNVEntityToSubjectGUID(nveTemp, subjectGUID);
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public String currentSubjectID() throws AccessException {
        // TODO Auto-generated method stub
        return (String) SecurityUtils.getSubject().getPrincipal();
    }

    @Override
    public String currentSubjectGUID() throws AccessException {
        UUID subjectGUID = SecurityUtils.getSubject().getPrincipals().oneByType(UUID.class);
        return subjectGUID != null ? subjectGUID.toString() : null;
    }




    public final  boolean isNVEntityAccessible(NVEntity nve, CRUD ...permissions)
            throws NullPointerException, IllegalArgumentException
    {
        return isNVEntityAccessible(Const.LogicalOperator.AND, nve, permissions);
    }


    public final  boolean isNVEntityAccessible(Const.LogicalOperator lo, NVEntity nve, CRUD ...permissions)
            throws NullPointerException, IllegalArgumentException
    {
        try
        {
            checkNVEntityAccess(lo, nve, permissions);
            return true;
        }
        catch(AccessException e)
        {
            //e.printStackTrace();
            return false;
        }
    }


    public final String checkNVEntityAccess(NVEntity nve, CRUD ...permissions)
            throws NullPointerException, IllegalArgumentException, AccessException

    {
        return checkNVEntityAccess(Const.LogicalOperator.AND, nve, permissions);
    }


    public final String checkNVEntityAccess(Const.LogicalOperator lo, NVEntity nve, CRUD ...permissions)
            throws NullPointerException, IllegalArgumentException, AccessException
    {
        SharedUtil.checkIfNulls("Null NVEntity", lo, nve);

        if (nve instanceof APICredentialsDAO || nve instanceof APITokenDAO)
        {
            return nve.getSubjectGUID();
        }

        String subjectGUID = currentSubjectGUID();

        if (subjectGUID == null || nve.getSubjectGUID() == null)
        {
            throw new AccessException("Unauthenticated subject: " + nve.getClass().getName());
        }

        if (!nve.getSubjectGUID().equals(subjectGUID))
        {

            if (permissions != null && permissions.length > 0)
            {
                boolean checkStatus = false;
                for(CRUD permission : permissions)
                {
                    String pattern = SharedUtil.toCanonicalID(':', "nventity", permission, nve.getGUID());
                    checkStatus = ShiroUtil.isPermitted(pattern);
                    if ((checkStatus && Const.LogicalOperator.OR == lo) ||
                            (!checkStatus && Const.LogicalOperator.AND == lo))
                    {
                        // we are ok
                        break;
                    }

                }
                if(checkStatus)
                    return nve.getSubjectGUID();
            }

            if(log.isEnabled()) log.getLogger().info("nveUserID:" + nve.getSubjectGUID() + " subjectGUID:" + subjectGUID);
            throw new AccessException("Access Denied. for resource:" + nve.getGUID());
        }

        return subjectGUID;
    }




    @Override
    public final boolean isNVEntityAccessible(String nveRefID, String nveUserID, CRUD... permissions) {
        SharedUtil.checkIfNulls("Null reference ID.", nveRefID);

        String userID = currentSubjectID();

        if (userID != null && nveUserID != null)
        {
            if (!nveUserID.equals(userID))
            {
                if (permissions != null && permissions.length > 0)
                {

                    for(CRUD permission : permissions)
                    {
                        if (!ShiroUtil.isPermitted(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID)))
                        {
                            return false;
                        }
                    }

                    return true;
                }

                //if(log.isEnabled()) log.getLogger().info("NVEntity UserID:" + nveUserID + " UserID:" + userID);
            }
            else
            {
                return true;
            }
        }

        return false;
    }
}
