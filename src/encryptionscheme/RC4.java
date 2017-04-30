package encryptionscheme;
/**
 * This class represents the RC4 encryption algorithm. Obtained from a online library.
 * @author Jabo Johnigan
 * @version 4/29/17
 * 
 */
public class RC4 {
    private int[] S = new int[256];
    private int[] T = new int[256];
    private int keylen;

    public RC4(byte[] key) throws Exception {
        if (key.length < 1 || key.length > 256) {
            throw new Exception("key must be between 1 and 256 bytes");
        } else {
            keylen = key.length;
            for (int i = 0; i < 256; i++) {
                S[i] = i;
                T[i] = key[i % keylen];
            }
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + S[i] + T[i]) % 256;
                S[i] ^= S[j];
                S[j] ^= S[i];
                S[i] ^= S[j];
            }
        }
    }

    public int[] encrypt(int[] plaintext) {
        int[] ciphertext = new int[plaintext.length];
        int i = 0, j = 0, k, t;
        for (int counter = 0; counter < plaintext.length; counter++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];
            t = (S[i] + S[j]) % 256;
            k = S[t];
            ciphertext[counter] = plaintext[counter] ^ k;
        }
        return ciphertext;
    }

    public int[] decrypt(int[] ciphertext) {
        return encrypt(ciphertext);
    }


}