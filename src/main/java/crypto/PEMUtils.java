package crypto;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class PEMUtils {
    private final static String PUB_KEY_TYPE = "PUBLIC KEY";
    private final static String PRI_KEY_TYPE = "PRIVATE KEY";

    private static String toPEM(String type, byte[] content) throws IOException {
        PemObject pemObject = new PemObject(type, content);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.flush();
        return stringWriter.toString();
    }

    private static byte[] getContent(String pem) throws IOException {
        StringReader stringReader = new StringReader(pem);
        PemReader pemReader = new PemReader(stringReader);
        PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    public static String convertPublicKeyToPEM(PublicKey publicKey) throws IOException {
        byte[] der = DERUtils.convertPublicKeyToDER(publicKey);
        return toPEM(PUB_KEY_TYPE, der);
    }

    public static String convertPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        byte[] der = DERUtils.convertPrivateKeyToDER(privateKey);
        return toPEM(PRI_KEY_TYPE, der);
    }

    public static PublicKey convertPEMToPublicKey(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] der = getContent(pem);
        return DERUtils.convertDERToPublicKey(der);
    }

    public static PrivateKey convertPEMToPrivateKey(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] der = getContent(pem);
        return DERUtils.convertDERToPrivateKey(der);
    }
}
