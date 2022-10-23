package test;

import crypto.DERUtils;
import crypto.ECCUtils;
import org.bouncycastle.asn1.ASN1Encodable;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

class DERUtilsTest {
    private static void doTest(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] privateKeyDER = DERUtils.convertPrivateKeyToDER(keyPair.getPrivate());
        byte[] publicKeyDER = DERUtils.convertPublicKeyToDER(keyPair.getPublic());
        System.out.println(Arrays.toString(privateKeyDER));
        System.out.println(Arrays.toString(publicKeyDER));

        PrivateKey privateKey = DERUtils.convertDERToPrivateKey(privateKeyDER);
        PublicKey publicKey = DERUtils.convertDERToPublicKey(publicKeyDER);
        System.out.println(privateKey);
        System.out.println(publicKey);

        ASN1Encodable privateKeyAlgorithmIdentifier = DERUtils.extractAlgorithmIdentifierFromPrivateKeyDER(privateKeyDER);
        ASN1Encodable publicKeyAlgorithmIdentifier = DERUtils.extractAlgorithmIdentifierFromPublicKeyDER(publicKeyDER);
        System.out.println(privateKeyAlgorithmIdentifier);
        System.out.println(publicKeyAlgorithmIdentifier);

        byte[] publicKeyBytes = DERUtils.extractPublicKeyBytesFromDER(publicKeyDER);
        System.out.println(publicKeyBytes.length);
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = ECCUtils.generateK1KeyPair();
        doTest(keyPair);

        keyPair = ECCUtils.generateR1KeyPair();
        doTest(keyPair);
    }
}
