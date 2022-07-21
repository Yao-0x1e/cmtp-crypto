package example;

import crypto.ECCUtils;

import java.security.*;

public class ECCExample {
    private static void doTest1(PrivateKey privateKey, String encrypted) throws Exception {
        System.out.println(encrypted);
        String decrypted = ECCUtils.decrypt(privateKey, encrypted);
        System.out.println(decrypted);
    }

    private static void doTest2(KeyPair keyPair, String message) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        String signature = ECCUtils.sign(keyPair.getPrivate(), message);
        System.out.println(signature);
        boolean verificationResult = ECCUtils.verify(keyPair.getPublic(), signature, message);
        System.out.println(verificationResult);
    }

    public static void main(String[] args) throws Exception {
        String str = "HelloWorld";
        KeyPair keyPair = ECCUtils.generateK1KeyPair();
        String encrypted = ECCUtils.encryptByK1(keyPair.getPublic(), str);
        doTest1(keyPair.getPrivate(), encrypted);
        doTest2(keyPair, str);

        keyPair = ECCUtils.generateR1KeyPair();
        encrypted = ECCUtils.encryptByR1(keyPair.getPublic(), str);
        doTest1(keyPair.getPrivate(), encrypted);
        doTest2(keyPair, str);
    }
}
