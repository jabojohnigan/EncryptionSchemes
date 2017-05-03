package encryptionscheme;
/**
 * This class represents the RC4 encryption algorithm.
 * @author Jabo Johnigan
 * @version 4/29/17
 * 
 */
public class RC4 {
        private int keylength;
        private int datalength;

    /**
     * Set up the key length and data length array then call the rc4_encrytion message
     * @param key to be generated
     * @param data the message from the file
     * @throws Exception throws an input exception
     */
    public RC4(final byte[] key,final byte[] data) throws Exception {
        keylength = key.length;
        datalength = data.length;
        rc4_encrypt(key, data);
    }

    /**
     * Encrypt the data/message
     * @param key key for the encryption
     * @param data the data of the incoming file.
     */
    private void rc4_encrypt(final byte[] key,final byte[] data){

        int i;
        int j;

        // key scheduling
        byte[] sbox = new byte[256];
        for (i = 0; i < 256; i++) {
            sbox[i] = (byte) i;
        }
        j = 0;
        for (i = 0; i < 256; i++) {
            j = ((j + sbox[i] + key[i % keylength]) % 256) & 0xFF;
            byte tmp = sbox[i];
            sbox[i] = sbox[j];
            sbox[j] = tmp;
        }

        // generate output
        i = 0;
        j = 0;
        int index = 0;
        while (index < datalength) {
            i = ((i + 1) % 256) & 0xFF;
            j = ((j + sbox[i]) % 256) & 0xFF;

            byte tmp = sbox[i];
            sbox[i] = sbox[j];
            sbox[j] = tmp;

            byte k = (sbox[((sbox[i] + sbox[j]) % 256) & 0xFF]);
            data[index] ^= k;

            index++;
        }
    }
}