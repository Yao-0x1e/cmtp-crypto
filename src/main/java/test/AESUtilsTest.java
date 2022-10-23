package test;

import crypto.AESUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class AESUtilsTest {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String str = "HelloWorld";
        String key = "TestKey";
        System.out.println(str);
        System.out.println(key);

        String encrypted = AESUtils.encrypt(str, key);
        System.out.println(encrypted);
        String decrypted = AESUtils.decrypt(encrypted, key);
        System.out.println(decrypted);
    }
}
