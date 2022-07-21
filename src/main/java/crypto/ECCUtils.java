package crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class ECCUtils {
    static {
        BCUtils.addBCProviderIfNull();
    }

    private final static String K1_CURVE_NAME = "secp256k1";
    private final static String R1_CURVE_NAME = "prime256v1";
    private final static ECGenParameterSpec EC_GEN_PARAMETER_SPEC_K1 = new ECGenParameterSpec(K1_CURVE_NAME);
    private final static ECGenParameterSpec EC_GEN_PARAMETER_SPEC_R1 = new ECGenParameterSpec(R1_CURVE_NAME);
    private final static int PUBLIC_KEY_LENGTH = 65;
    private final static int MAC_LENGTH = 32;
    private final static String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private final static String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private final static String ASYMMETRIC_KEY_ALGORITHM = "EC";
    private final static String ASYMMETRIC_KEY_PROVIDER = "BC";
    private final static String SYMMETRIC_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    private final static String SYMMETRIC_KEY_ALGORITHM = "AES";

    private static KeyPair generateKeyPair(ECGenParameterSpec ecGenParameterSpec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_KEY_ALGORITHM, ASYMMETRIC_KEY_PROVIDER);
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateK1KeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return generateKeyPair(EC_GEN_PARAMETER_SPEC_K1);
    }

    public static KeyPair generateR1KeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return generateKeyPair(EC_GEN_PARAMETER_SPEC_R1);
    }

    private static boolean equalConstTime(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < b1.length; i++) {
            result |= b1[i] ^ b2[i];
        }
        return result == 0;
    }

    private static byte[] symmetricEncrypt(byte[] key, byte[] plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plainText);
    }

    private static byte[] symmetricDecrypt(byte[] key, byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(cipherText);
    }

    private static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(otherPublicKey, true);
        return keyAgreement.generateSecret();
    }

    private static byte[] encrypt(PublicKey publicKey, byte[] bytes, String curveName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // 生成临时密钥对
        KeyPair ephemeralKeyPair;
        if (curveName.equals(K1_CURVE_NAME)) {
            ephemeralKeyPair = generateK1KeyPair();
        } else if (curveName.equals(R1_CURVE_NAME)) {
            ephemeralKeyPair = generateR1KeyPair();
        } else {
            throw new InvalidAlgorithmParameterException("Unknown elliptic curve name: " + curveName);
        }

        // 通过ECDH协议计算出SharedSecret
        byte[] sharedSecret = generateSharedSecret(ephemeralKeyPair.getPrivate(), publicKey);

        // 对SharedSecret进行哈希并切分得到加密密钥和MAC密钥
        byte[] hash = SHAUtils.hash(sharedSecret);
        int hashMidIndex = hash.length / 2;
        byte[] encryptionKey = Arrays.copyOfRange(hash, 0, hashMidIndex);
        byte[] macKey = Arrays.copyOfRange(hash, hashMidIndex, hash.length);

        // 对消息进行加密并计算MAC
        byte[] cipherText = symmetricEncrypt(encryptionKey, bytes);
        byte[] tag = MACUtils.mac(cipherText, macKey);

        // 拼接临时公钥、密文和MAC得到加密结果
        byte[] publicKeyDER = DERUtils.convertPublicKeyToDER(ephemeralKeyPair.getPublic());
        byte[] publicKeyBytes = DERUtils.extractPublicKeyBytesFromDER(publicKeyDER);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(publicKeyBytes);
        out.writeBytes(cipherText);
        out.writeBytes(tag);
        return out.toByteArray();
    }

    private static byte[] decrypt(PrivateKey privateKey, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NoSuchProviderException {
        // 切割消息
        byte[] otherPublicKeyBytes = Arrays.copyOfRange(bytes, 0, PUBLIC_KEY_LENGTH);
        byte[] cipherText = Arrays.copyOfRange(bytes, PUBLIC_KEY_LENGTH, bytes.length - MAC_LENGTH);
        byte[] messageTag = Arrays.copyOfRange(bytes, bytes.length - MAC_LENGTH, bytes.length);

        byte[] privateKeyDER = DERUtils.convertPrivateKeyToDER(privateKey);
        ASN1Encodable algorithmIdentifier = DERUtils.extractAlgorithmIdentifierFromPrivateKeyDER(privateKeyDER);
        PublicKey otherPublicKey = DERUtils.convertDERToPublicKey(DERUtils.buildDERFromPublicKeyBytes(otherPublicKeyBytes, algorithmIdentifier));

        // 获取SharedSecret
        byte[] sharedSecret = generateSharedSecret(privateKey, otherPublicKey);

        byte[] hash = SHAUtils.hash(sharedSecret);
        int hashMidIndex = hash.length / 2;
        byte[] encryptionKey = Arrays.copyOfRange(hash, 0, hashMidIndex);
        byte[] macKey = Arrays.copyOfRange(hash, hashMidIndex, hash.length);
        byte[] keyTag = MACUtils.mac(cipherText, macKey);
        assert equalConstTime(messageTag, keyTag);

        return symmetricDecrypt(encryptionKey, cipherText);
    }

    public static String encryptByK1(PublicKey publicKey, String str) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encrypt(publicKey, bytes, K1_CURVE_NAME);
        return Base64.encodeBase64String(encrypted);
    }

    public static String encryptByR1(PublicKey publicKey, String str) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encrypt(publicKey, bytes, R1_CURVE_NAME);
        return Base64.encodeBase64String(encrypted);
    }

    public static String decrypt(PrivateKey privateKey, String base64Str) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchProviderException {
        byte[] encrypted = Base64.decodeBase64(base64Str);
        byte[] decrypted = decrypt(privateKey, encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static boolean verify(PublicKey publicKey, byte[] sig, byte[] bytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(bytes);
        return signature.verify(sig);
    }

    private static byte[] sign(PrivateKey privateKey, byte[] bytes) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(bytes);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, String base64Sig, String str) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] sig = Base64.decodeBase64(base64Sig);
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        return verify(publicKey, sig, data);
    }

    public static String sign(PrivateKey privateKey, String str) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        byte[] sig = sign(privateKey, data);
        return Base64.encodeBase64String(sig);
    }
}

