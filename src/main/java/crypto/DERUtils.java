package crypto;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DERUtils {
    static {
        BCUtils.addBCProviderIfNull();
    }

    private static final String ALGORITHM = "EC";
    private static final String PROVIDER = "BC";

    public static byte[] convertPublicKeyToDER(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    public static byte[] convertPrivateKeyToDER(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    public static PublicKey convertDERToPublicKey(byte[] encoded) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        return factory.generatePublic(spec);
    }

    public static PrivateKey convertDERToPrivateKey(byte[] encoded) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        return factory.generatePrivate(spec);
    }

    public static ASN1Encodable extractAlgorithmIdentifierFromPublicKeyDER(byte[] encoded) {
        ASN1Sequence sequence = DERSequence.getInstance(encoded);
        return sequence.getObjectAt(0);
    }

    public static ASN1Encodable extractAlgorithmIdentifierFromPrivateKeyDER(byte[] encoded) {
        ASN1Sequence sequence = DERSequence.getInstance(encoded);
        return sequence.getObjectAt(1);
    }

    public static byte[] extractPublicKeyBytesFromDER(byte[] encoded) {
        // SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
        // return spki.getPublicKeyData().getOctets();

        ASN1Sequence sequence = DERSequence.getInstance(encoded);
        DERBitString derBitString = (DERBitString) sequence.getObjectAt(1);
        return derBitString.getBytes();
    }

    public static byte[] buildDERFromPublicKeyBytes(byte[] publicKeyBytes, ASN1Encodable algorithmIdentifier) throws IOException {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(algorithmIdentifier);
        vector.add(new DERBitString(publicKeyBytes));
        DERSequence derSequence = new DERSequence(vector);
        return derSequence.getEncoded();
    }
}
