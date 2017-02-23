import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Thank you https://www.madirish.net/561 for your tutorial
 */
public class IVDemo {

    public static void main(String[] args) throws Exception {

        // Set message
        String secretMessage = "GGGGGGGGGGGGGGG\n" +
                "GGGGGGGGGGGGGGG\n" +
                "GGGGGGGGGGGGGGG\n" +
                "GGGGGGGGGGGGGGG\n" +
                "AAAAAAAAAAAAAAA\n" +
                "C";
        System.out.println("Message plain text:\t\t\t" + secretMessage);

        // Generate a new IV
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        System.out.print("IV:\t\t\t");
        for (byte b : iv)
            System.out.print(new Integer(b));
        System.out.print("\n");

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String encryptionKey = "ABCDEFGHIJKLMNOP";
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
//        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(secretMessage.getBytes());

        System.out.print("Cipher text:\t\t");
        for (byte b : cipherText)
            System.out.print(Integer.toHexString((int) b));
        System.out.print("\n");

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
//        cipher.init(Cipher.DECRYPT_MODE, key);
        String decryptedMessage = new String(cipher.doFinal(cipherText));
        System.out.println("Decrypted message:\t" + decryptedMessage);

    }

}
