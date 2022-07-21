package crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESUtils {
    // PKCS5默认块大小为8个字节
    private static final String CIPHER_ALGORITHM = "AES/CTR/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int IV_LENGTH = 16;

    private static byte[] encrypt(byte[] bytes, SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(bytes);
    }

    private static byte[] decrypt(byte[] bytes, SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(bytes);
    }

    public static String encrypt(String str, String key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // 取密钥的SHA256作为真正的密钥
        byte[] keySha56 = SHAUtils.hash(key);
        // 使用UTF-8编码将传入字符串转换为二进制数据
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        // 随机生成initializationVector
        byte[] initializationVector = new byte[IV_LENGTH];
        SECURE_RANDOM.nextBytes(initializationVector);
        // 使用AES对数据进行加密并编码为BASE64
        SecretKeySpec secretKeySpec = new SecretKeySpec(keySha56, KEY_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        byte[] encrypted = encrypt(data, secretKeySpec, ivParameterSpec);
        byte[] finalData = new byte[encrypted.length + IV_LENGTH];
        System.arraycopy(initializationVector, 0, finalData, 0, IV_LENGTH);
        System.arraycopy(encrypted, 0, finalData, IV_LENGTH, encrypted.length);
        return Base64.encodeBase64String(finalData);
    }

    public static String decrypt(String base64Str, String key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // 取密钥的SHA256作为真正的密钥
        byte[] keySha56 = SHAUtils.hash(key);
        // 使用BASE64对传入字符串进行解码
        byte[] base64 = Base64.decodeBase64(base64Str);
        // 切分BASE64为initializationVector和message
        byte[] initializationVector = Arrays.copyOfRange(base64, 0, IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(base64, IV_LENGTH, base64.length);
        // 对字符串进行AES解密
        SecretKeySpec secretKeySpec = new SecretKeySpec(keySha56, KEY_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        byte[] decrypted = decrypt(encrypted, secretKeySpec, ivParameterSpec);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
