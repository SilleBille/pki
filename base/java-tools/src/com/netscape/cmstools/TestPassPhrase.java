package com.netscape.cmstools;
/* This program tries to decrypt a passphrase stored by KRA using the value
 * stored inside LDAP
 */
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;

public class TestPassPhrase {

    private static boolean arraysEqual(byte[] bytes, byte[] ints) {
        if (bytes == null || ints == null) {
            return false;
        }

        if (bytes.length != ints.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != ints[i]) {
                return false;
            }
        }

        return true;
    }

    public static void main(String args[]) {
        System.out.println("Start!");
        CryptoToken mSourceToken = null;
        CryptoManager cm = null;
        X509Certificate mUnwrapCert = null;
        PrivateKey desiredPrivateKey = null;

        try {
            CryptoManager.initialize("/home/dmoluguw/test/test_kra_operation/");
        } catch (KeyDatabaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertDatabaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (AlreadyInitializedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            cm = CryptoManager.getInstance();
            mSourceToken = CryptoUtil.getKeyStorageToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

            Password mPwd = new Password("Secret.123".toCharArray());

            mSourceToken.login(mPwd);

        } catch (NotInitializedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchTokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IncorrectPasswordException e) {
            System.out.println("Wrong Password!!!");
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            mUnwrapCert = cm.findCertByNickname("kra_storage");
        } catch (ObjectNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (mUnwrapCert == null) {
            System.out.println("FAILURE to get source StorageCert!");
        }

        try {
            PrivateKey pk[] = mSourceToken.getCryptoStore().getPrivateKeys();

            for (int i = 0; i < pk.length; i++) {
                if (arraysEqual(pk[i].getUniqueID(),
                        ((TokenCertificate) mUnwrapCert).getUniqueID())) {
                    System.out.println("FOUND private key!!!");
                    desiredPrivateKey = pk[i];
                }
            }
        } catch (TokenException exToken) {
            System.out.println("Some exception at getting private key");
            exToken.printStackTrace();
        }

        // Payload to unwrap
        String ldapPassPhrase = "MIIBFgSCAQAdk0AR+xlOZ3GONkE6krrP0KH+WJpLnJHZXfN6wDNjnAunUzvSH\n" +
                " sS4ZdMaKJjLmAaVsz5Hm6G+GUYTuMDbGxjFmbZQk5NinpyZhkNG2yRb2etSLgiWTUJwUelDbFBsmf\n" +
                " IDQwzZi+zjV21GZpx28qJbKCNOUgDvi296EHWi3cEy+MYkGXOYmcDYe+Srek2Vnb/LftzgQAG6lZ3\n" +
                " oZDdKIlCRclPzf5Tn/Sls5+L1xIfUTKF0YPEFfBCgu7pCFy8ZXoxPaI/vIJj5CRGHg7nwZyFXHnzB\n" +
                " RMA+cwRuOuispq4mruNRRQUPfSKtmB+z2A+nS9EdKgyE/EFg7klyGofAtCaGBBBV6dMF0YZQmXcFK\n" +
                " Tl84hN3";

        byte[] wrappedKeyData = Utils.base64decode(ldapPassPhrase.toString());
        DerInputStream in;
        DerValue sequence_member[];
        byte[] source_session = null;
        byte[] encrypted_private_key = null;
        SymmetricKey sk = null;

        // Initialize Unwrap symmetric key
        //KeyWrapper source_rsaWrap = null;
        try {
            //val = new DerValue(wrappedKeyData);
            //in = val.data;
            in = new DerInputStream(wrappedKeyData);
            sequence_member = in.getSequence(2);
            System.out.println("Length of sequence_member: " + sequence_member.length);
            // Session Key
            source_session = sequence_member[0].getOctetString();
            System.out.println("Length of source_session: " + source_session.length);
            // Payload to be decrypted
            encrypted_private_key = sequence_member[1].getOctetString();
            System.out.println("Length of encrypted_private_key: " + encrypted_private_key.length);

            // source_rsaWrap = mSourceToken.getKeyWrapper(
            //        KeyWrapAlgorithm.RSA);
            // source_rsaWrap.initUnwrap(desiredPrivateKey, null);

            System.out.println("Base64 payload: " + Utils.base64encode(encrypted_private_key,true));

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // Start unwrap

        try {
            sk = CryptoUtil.unwrap(
                    mSourceToken,
                    SymmetricKey.Type.AES,
                    128,
                    SymmetricKey.Usage.DECRYPT,
                    desiredPrivateKey,
                    source_session,
                    KeyWrapAlgorithm.RSA);

            //sk = source_rsaWrap.unwrapSymmetric(source_session,
            //        SymmetricKey.AES,
            //        0);
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        System.out.println(Utils.base64encode(sk.getEncoded(), true)
                + "Length: " + sk.getEncoded().length
                + "\nOriginal key: " + Utils.normalizeString(Utils.base64encode(sk.getEncoded(), true)));

        // Try unwrapping the payload

        String IV = "VipB4FHWNwpBURG7zeo8kw==";

        IVParameterSpec ivSpec = new IVParameterSpec(Utils.base64decode(IV));

        //            try {
        //                KeyWrapper wrapper = mSourceToken.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
        //                wrapper.initUnwrap(sk, ivSpec);
        //                payload = source_rsaWrap.unwrapPrivate(encrypted_private_key, PrivateKey.RSA, public_key);
        //            } catch (InvalidKeyException | IllegalStateException | TokenException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
        //                // TODO Auto-generated catch block
        //                e.printStackTrace();
        //            }

        try {
            byte []retrievedData = CryptoUtil.decryptUsingSymmetricKey(mSourceToken,
                    ivSpec, encrypted_private_key, sk,
                    EncryptionAlgorithm.AES_128_CBC);

            System.out.println("FINAL Retrieved DATA: " + Utils.HexEncode(retrievedData));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

/*        try {
            SymmetricKey skTest = CryptoUtil.generateKey(
                    mSourceToken,
                    KeyGenAlgorithm.AES,
                    128,
                    null,
                    false);

            System.out.println("Test SK generation: " + Utils.base64encode(skTest.getEncoded(), true));

            KeyGenerator kg = mSourceToken.getKeyGenerator(KeyGenAlgorithm.AES);
            kg.temporaryKeys(false);
            kg.initialize(128);
            System.out.println("Key Gen: " + Utils.base64encode(kg.generate().getKeyData(), true));

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }*/

        System.out.println("End!");
    }

}
