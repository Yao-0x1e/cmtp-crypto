package crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MACUtils {
    private static final String ALGORITHM = "HmacSHA256";

    public static byte[] mac(String str, byte[] macKey) throws NoSuchAlgorithmException, InvalidKeyException {
        return mac(str.getBytes(StandardCharsets.UTF_8), macKey);
    }

    public static byte[] mac(byte[] bytes, byte[] macKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(new SecretKeySpec(macKey, ALGORITHM));
        return mac.doFinal(bytes);
    }
}
