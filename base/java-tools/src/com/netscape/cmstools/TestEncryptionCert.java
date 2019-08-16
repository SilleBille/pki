package com.netscape.cmstools;
/* This program tries to retrieve the entity's encryption cert's private key
 * from ldap stored value
 */
import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;



public class TestKeyAscheel {

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
        String originalPrivKey = "MIIF2ASCAQASlnioCa6GRP4lbwF+9TVDYX73jo841vPvQejq3wS0evzZhRUu7\n" +
                " 4Pm7Kwq6kUeU9oXsPtRArAeK7y2sh6oslcyHgEX1qhcTrH5xD7r9BDcIuzSGe1UgBHmsz1xJhH8BJ\n" +
                " QPP25wobP0ooN0K7vzdRWC5RmCnSIrxRroXdO/l9kQPP8Mmmm30tzqLLVB/S58NFCTnKWo4yUBYbf\n" +
                " 5Pq6Cf5Y3zEHUhtbAihTMQdJznKV3G+xJEc5cLcVo4LnAiTRCdFPiuEu5BJagHvZqDKgJYhu8Z5lT\n" +
                " IS6OrceXavXW6BxQzBI+D0rLuO1aq1ZePSePXJiAVWrk5iPt4YaMyj/O4t9EBIIE0FQWvxcAvDwZD\n" +
                " AbtDWk2X58Aw1cVx2IwXf//Vf5AlciiZ+ZiOM/Hjr+1r9LD8+P4xsBL7gYsrFOF47ozh3Pr3vImxm\n" +
                " 5t18jYiCMHJp/fxhVhiNXBMGI1TBTKPtdFQG31UqYNubco95TK2aWpf3t+HSLKSgYoFgqjPqCRwU0\n" +
                " 9eOT2SZsKOVKtcW6FyH/QjRp1oAqoUmjzz6f1HJCYnWVG9BLlfUirwxN2hV+8kL1tt8+ioADei585\n" +
                " PKT7v9+UQgh41nAaLrS1aevOFy5KRYaLjypFix7ktDBVFvmXpSL98IzVLUo68uHxmvd2OnwBeIf8Y\n" +
                " jspPS2b8fK63OZ9MvNG+r9QeSX/VC4EqGzf7zkgQCgvtsLcxet2OLIwfLlh56BrOV0ThDdVbz572h\n" +
                " C5Z3oajbEYBe7AiY/zIfnC348QuJlBGr6TN9GWBWiJy8SwOZl3/i88qKXXynDu07j7ukM64TaIh3R\n" +
                " 1OiPvJcBJhLeVqKQ7GdDGbTSPao4eTEOBH8H4KwjO/ymOrRm+yjbwyNxkdNWHjqNe+xJfZ9E4IGqk\n" +
                " 7XtHLfhA57/rbOBcWx2UEENm5/yvVWI2kM9LO7tZEfPp9BbGmDsL+uG2FA1K6GbVwkLMfS6EiVr6S\n" +
                " CJ8i+l2gPtJzhllaIpR8yTU1FG0gsyq7NepH6UgBA21OS/JFII2a6eMmSD5FdcJ1PN2wiNG6PHh6V\n" +
                " 1+JE9ZnxoC6X9ragnCT+wAljLInIUIwTaEx1EBx+StfOt4JKhDSNgBvVEpkYtjZq6LQuwTapx8Jdy\n" +
                " 7uCfkB8REVxuBzdlTUVsRJmHK0d1OapAGwjg4a722LOHzvRtRXrG82YFgQabZFA4K5qxGQfCzvYc9\n" +
                " bJ2Om/ZrxSNfjg84TeAG9Eu1cbJ0kBZBtJeOb34E79vfDKrADjLtFpF5jbvCJTKq+rglf7XPq/f5Z\n" +
                " ueqTyNX1dq9jRk91PCT4SSfFcocXbruPELMAgPn71oa2MK3GdqBXNDoNIxBp3w3esieWvhv7o5JGb\n" +
                " jpDY5ifsNEyaOYUCiSPKA4v5xddE6X0+YdJ8sTMsA1761N4P/tV6XIadNEYuhYCMEUnrdtBqBbFVA\n" +
                " H43fp3BGR5cMgc9yN8vUXz3aL1U4X+IeMPxgaH5+tfd/bWTR2YTYNyBd3bPMoYjl4EtlKEUoFzwv9\n" +
                " sJOMIhM3Clxl8XlWrtuwqcceXM3alfEShKafSwJZoSpuXB6LOJ3L4Zd36HP6EPehLGoh+6VhPCUwQ\n" +
                " 8MOHZGQKbLgUQswFaIkNAJ1irhQvnP1my3o4qHxL3A7AuyRh53vpJ9MuUr7yswmxxyrFPyjbIP9Ir\n" +
                " Ggu7SulaqoaPyh7PBJ5+VINagKt2Z0Z8FPYGikCXUFPmUHNatA4CfvOho6s3xceuLObCeH5lHwO+O\n" +
                " RmAwFE2BIotAnEY0T6sd274++riBn4NozdVm/4MlN7fumnCE98VNCtX3Xs+ZUL2AWoQ+1s1jAZHbj\n" +
                " VEZlCgPhLDfNKyVgNktIWniW/nUaS7ouTmG3D0LPm8upv/Na7HEy9mmGdXpce/v8rMCa8JXG0sf8U\n" +
                " ogxhMpqYUk6ZsuK/bWcO4x+HEJFFUk21Z7Koq6iVYJLmuoqtDwG7WgxhAPEZtEM4tmj0YTHiaWCUA\n" +
                " HFW5PR0KJF1dSp";

        byte[] wrappedKeyData = Utils.base64decode(originalPrivKey.toString());
        DerValue val;
        DerInputStream in;
        DerValue sequence_member[];
        byte[] source_session = null;
        byte[] encrypted_private_key = null;
        SymmetricKey sk = null;

        // Initialize Unwrap symmetric key
        KeyWrapper source_rsaWrap = null;
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

            source_rsaWrap = mSourceToken.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);
            source_rsaWrap.initUnwrap(desiredPrivateKey, null);

        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // Start unwrap

        try {
            /*sk = source_rsaWrap.unwrapSymmetric(source_session,
                    SymmetricKey.AES,
                    SymmetricKey.Usage.UNWRAP,
                    0);*/

            sk = CryptoUtil.unwrap(
                    mSourceToken,
                    SymmetricKey.AES,
                    128,
                    SymmetricKey.Usage.UNWRAP,
                    desiredPrivateKey,
                    source_session,
                    KeyWrapAlgorithm.RSA);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(Utils.base64encode(sk.getEncoded(), true)
                + "Length: " + sk.getEncoded().length
                + "\nOriginal key: " + Utils.normalizeString(Utils.base64encode(sk.getEncoded(), true)));

        // PUBLIC KEY FOR WHICH THE PRIVATE KEY IS TRYING TO BE RETRIEVED

        String origPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5sejhz8+zjh3PUXPvcv+" +
                "ygVSLh7BVjUAVOq3WbLWgkApmB/LUvcYVGa+sEHP7LXiCLjrbgqWP3+Y0x8ibLeu" +
                "zfoRtO5HY+5flzWrqPWkYw05XQssA9bmacC8wl3N4utLiGZXjnw1/oRU3ErfG7p7" +
                "p1cb4rPY/UmbO1q0XgkShpc4PUbkl2HsDCHRwzXOYGh6IqoBG9W6uVk4Aq2lt8h7" +
                "DJd4oX7uctlb4f9BZ298rydJ8FDNmbrZ6jSX4r1oV3G4r9Z0PLWFqCbs+ayNAc4d" +
                "/a+Q92A5tX5b98xY0wiRVTVN8egwKN+9U1P0Ph5NPP4kAWhZUZGISDJxjbkdDzVr" +
                "SQIDAQAB";

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(origPublicKey));

        KeyFactory kf = null;
        PublicKey public_key = null;
        try {
            kf = KeyFactory.getInstance("RSA");

            public_key = kf.generatePublic(keySpecX509);
        } catch (Exception e1) {
            // TODO Auto-generated catch block
            System.out.println("HEre?");
            e1.printStackTrace();
        }

        System.out.println("Public key type: " + public_key.getAlgorithm());

        // Try unwrapping the payload

        String IV = "kvBPCKJWoUXDwxfYMZa0/g==";

        System.out.println(Utils.base64decode(IV) == (IV.getBytes()));

        IVParameterSpec ivSpec = new IVParameterSpec(Utils.base64decode(IV));


        //            try {
        //                KeyWrapper wrapper = mSourceToken.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
        //                wrapper.initUnwrap(sk, ivSpec);
        //                payload = source_rsaWrap.unwrapPrivate(encrypted_private_key, PrivateKey.RSA, public_key);
        //            } catch (InvalidKeyException | IllegalStateException | TokenException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
        //                // TODO Auto-generated catch block
        //                e.printStackTrace();
        //            }
        PrivateKey retrievedData = null;
        try {

            System.out.println(KeyWrapAlgorithm.AES_KEY_WRAP_PAD);
            retrievedData = CryptoUtil.unwrap(
                    mSourceToken,
                    public_key,
                    false,
                    sk,
                    encrypted_private_key,
                    KeyWrapAlgorithm.AES_KEY_WRAP_PAD,
                    null);

            System.out.println("Private key is null? " + (retrievedData == null));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        PasswordConverter passConverter = new
                PasswordConverter();

        String pwd = "Secret.123";
        char[] pwdChar = pwd.toCharArray();
        org.mozilla.jss.util.Password pass = new
                org.mozilla.jss.util.Password(
                        pwdChar);

        byte[] salt = Utils.base64decode("Hxt3m/xJPT1Q4DuIIYs6PS6kQhw=");

        ASN1Value key = null;
        try {
            key = EncryptedPrivateKeyInfo.createPBE(
                    PBEAlgorithm.PBE_SHA1_DES3_CBC,
                    pass, salt, 1, passConverter, retrievedData, mSourceToken);

            System.out.println("IS null? " + (key == null));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CharConversionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NotInitializedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        SEQUENCE safeContents = new SEQUENCE();

        SafeBag keyBag = new SafeBag(
                SafeBag.PKCS8_SHROUDED_KEY_BAG, key, null); // ??

        safeContents.addElement(keyBag);

        // build contents
        AuthenticatedSafes authSafes = new
                AuthenticatedSafes();

        authSafes.addSafeContents(
                safeContents
                );
        PFX pfx = new PFX(authSafes);

        try {
            pfx.computeMacData(pass, null, 5);

            ByteArrayOutputStream fos = new
                    ByteArrayOutputStream();
            pfx.encode(fos);
            // put final PKCS12 into volatile request
            System.out.println(Utils.base64encode(fos.toByteArray(), true));
        } catch (DigestException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CharConversionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NotInitializedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }



        System.out.println("End!");
    }

}
