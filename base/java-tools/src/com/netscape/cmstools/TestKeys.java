    package com.netscape.cmstools;

    import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
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

    public class TestKeys {

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

                Password mPwd = new Password("A6)^!?bM2)%!".toCharArray());

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
                mUnwrapCert = cm.findCertByNickname("storageCert cert-pkitest KRA");
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
                                      ((TokenCertificate)
                                        mUnwrapCert).getUniqueID())) {
                        System.out.println("FOUND private key!!!");
                        desiredPrivateKey = pk[i];
                    }
                }
            } catch (TokenException exToken) {
                System.out.println("Some exception at getting private key");
                exToken.printStackTrace();
            }

            // Payload to unwrap
            String originalPrivKey = "MIIF2ASCAQBlAuJoYh4mNBtwrRmJHI/5JTaqzaWIeMbB10g1Gm53PFU9G0mPl\n" +
                    " rensn9PQuMl3GLeYXJiB9GjK8MRmLPYFeyHXNWzHjcT0VeXfCgaJTIAf8TPGPT5OFwqlyevFEp0Kl\n" +
                    " NuRitzMkffc+k+P3e4OMPwpgYY19JGgMgMCKeZe3sA5LLs60PfkpRTGgcceLp4Iv8I5o7WzVBzMPF\n" +
                    " pNvkOXpVPBrfx+9od8gTFHvj1ic6mq1ux99TX+WTre2Jg/qWNel5OIspHVVlXP7mUZNgiMCrI0LOb\n" +
                    " a5dnwEYLO3MaZMVm8qIOvA8t3e2lrKdQPaOZn5CbGE7ntRxWYGbxiumVTzxwBIIE0A5jn0nJtc75M\n" +
                    " UIySccpODDs5ANpgpq9lDOeIdgc6toZPo1abEodSKeQ/S+22fQrDhUZ62GK89jVLE8MTU8wQsYx7H\n" +
                    " ZifU6Ox79yU6lCDcIstXTYqrtNuY7UCRXsv12KD3TN78816hOTDoaNYKpQyQ0WDJ7LOL67wMpPspD\n" +
                    " LzmtQNlK/dBhfGusQtH1ITrXiCxFAehe+gdfsvFqEdojxk2oHfwJkZlmeAiKUKslh0+mepDbGWHbk\n" +
                    " UTmlnjWAln5Ojo/C+TO44inEntMrGPUqbOvmQiWBOosVJBBTkRCfjANC5ICO4FUKsi/KPFd6msjFk\n" +
                    " 9RiVS6QEr+cipTdM1myYX4YJggEWUgJblT2cvcp5cUQJ9OkICWYO6UwVvKVqJiPRU+mPgnMkFu0mK\n" +
                    " vKNzmjE5WRfrqxXKADXird7LBb61eLA0bB10orly4j1WeTQNMSVRU+P0Y5MdAOKsigxDjV6ZFTYnI\n" +
                    " kno8hmGcpQq9VJJj/mPq05UxQ/NQb49zlvOEhmSoDxJR/ghiYtkRsVJawH5pO/APIuUcyYALFyOgd\n" +
                    " xGhxFoMMHKBeq5KDnTUpLp1fBqqfic+JNqGLJ2uF/czmafL96zDdCm/P4HdvMxeDitpSv/Y348WnA\n" +
                    " rOP/c6EwPD4Bry/V6RMN2ZA1zKvalvKesR4MRXSVeBSUo+NyJqKppV/bn79Gb8lFIRJBPcpIZbwk9\n" +
                    " KEwEZ5Bq4lkNdBJ/p3FAIk+4aLtPpzS0xVz/hBSwhjUk70JLNaK69zHOvg/uG9ndu2cJXSGOu5a4U\n" +
                    " t7jNDPQK0G08t4yYshhui+m6X4h2XqfZKwVmLOpOLv4BmDePcK5ExrFBqnCOlZTJzpyko0UvTuvPC\n" +
                    " CIK+oMt1++bAmCGbaHfStkL8jqIiDqPc2VuIJGP0NNZAyEyjuOs2YZAuKO6FYK6/aDXOU/HgD60K3\n" +
                    " cCOQqq+MW0Qi7BAx15hUi2A6Uv8ZiBGxPMYj5xc2/7wWrAo0ZqKJtRxwt8fyC9r9GCvaBtuiSyFPq\n" +
                    " +1FUTdSqb8VtdHb+a5N1WLP2JTEmU3bNJ7J5RLco94Y9/HOOucxtyULrkFgHPmKXiOnss58lbVV7A\n" +
                    " 5j1Oim8u+JVbc42cZgF1kdHXYIzob4sOr+l6alzez5Gljtf7SO+MMD9zOXhqeJ4+7OJ4N4P9i13NW\n" +
                    " mMgOe0E9aMMmFmP2wpRqQeYXcfh+CdSs0ufqoE/BE3NZy6LvfvGK3OaQqiiFlN5maMwN2oKgZWkrQ\n" +
                    " WydO7BBy61SogNIYg0lBpkP/8WgWILdtmReMJr29oNXnfbRlBnXwD81zN4WayyurK2qd+ENtVoFXi\n" +
                    " 3nJvG65u4QnL0k4BiQwgmFZt9e+hUzUeGCLLlvzgojsAhVI58ftKqMCtr/iyfmLPQEBWsk2OtqPYn\n" +
                    " 26VOfNnQBo29mTzOBedXXOu91I+MszIOp3NkQ+f0ea2EfZG6EXmqY5ae8lIIdXx2q/21XUxnYxSUk\n" +
                    " 1D3eYI8mntZFYmrHIX82TWAkVpBIRTpyzQ1lLloSU4urV/Tj3/EnyxP1r0+g8OlOxGtjvlTA/jlF8\n" +
                    " uF0yClE5Zyymn6WVc419/Zl/+oXczUckg0MgCrIYQTMywFtsDU+5IfgbXQnnvVoKLHrgf4J3GG6v+\n" +
                    " G0SRcsSfUEU/Ou";


            byte []wrappedKeyData = Utils.base64decode(originalPrivKey.toString());
            DerValue val;
            DerInputStream in;
            DerValue dSession;
            byte source_session[] = null;
            SymmetricKey sk = null;

            // Initialize Unwrap symmetric key
            KeyWrapper source_rsaWrap = null;
            try {
                val = new DerValue(wrappedKeyData);
                in = val.data;
                dSession = in.getDerValue();
                System.out.println(dSession.length());
                System.out.println(in.getDerValue().length());
                source_session = dSession.getOctetString();
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
                sk = source_rsaWrap.unwrapSymmetric(source_session,
                        SymmetricKey.AES,
                        SymmetricKey.Usage.DECRYPT,
                        0);
            } catch (IllegalStateException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (TokenException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            System.out.println(Utils.base64encode(sk.getEncoded(),true)
            + "Length: " + sk.getEncoded().length
            + "\nOriginal key: " + Utils.normalizeString(Utils.base64encode(sk.getEncoded(), true)));

            System.out.println("End!");
        }

    }
