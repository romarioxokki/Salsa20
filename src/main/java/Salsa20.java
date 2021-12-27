import java.io.*;
import java.nio.charset.StandardCharsets;

public class Salsa20 implements StreamCipher {

    private final static int stateSize = 16;

    private final static byte[]
            gamma1 = "expand 32-byte k".getBytes(),
            gamma2 = "expand 16-byte k".getBytes();


    private int index = 0;
    private int[] y = new int[stateSize];
    private int[] x = new int[stateSize];
    private byte[] keyStr = new byte[stateSize * 4],
            key = null,
            IV = null;
    private boolean initialised = false;

    private int cW0, cW1, cW2;

    public void engineInitEncrypt(byte[] key, byte[] iv) {
        init(true, key, iv);
    }

    public void engineInitDecrypt(byte[] key, byte[] iv) {
        init(false, key, iv);
    }


    private void init(
            boolean forEncryption,
            byte[] key, byte[] iv) {


        if (iv == null || iv.length != 8) {
            throw new IllegalArgumentException("Salsa20 requires exactly 8 bytes of IV");
        }


        key = key;
        IV = iv;

        setKey(key, IV);
    }

    public byte returnByte(byte in) {
        if (limitExceeded()) {
            System.out.println("2^70 byte limit per IV; Change IV");
        }

        if (index == 0) {
            salsa20WordToByte(y, keyStr);
            y[8]++;
            if (y[8] == 0) {
                y[9]++;
            }
        }
        byte out = (byte) (keyStr[index] ^ in);
        index = (index + 1) & 63;

        return out;
    }

    public final byte[] crypt(byte[] data, int position, int length) {
        byte[] buffer = new byte[length];
        crypt(data, position, length, buffer, 0);
        return buffer;
    }


    public void crypt
            (
                    byte[] in,
                    int inOff,
                    int len,
                    byte[] out,
                    int outOff) {


        for (int i = 0; i < len; i++) {
            if (index == 0) {
                salsa20WordToByte(y, keyStr);
                y[8]++;
                if (y[8] == 0) {
                    y[9]++;
                }
            }
            out[i + outOff] = (byte) (keyStr[index] ^ in[i + inOff]);
            index = (index + 1) & 63;
        }
    }

    public void reset() {
        setKey(key, IV);
    }


    private void setKey(byte[] keyBytes, byte[] ivBytes) {
        key = keyBytes;
        IV = ivBytes;

        index = 0;
        resetCounter();
        int rotate = 0;
        byte[] constants;

        y[1] = byteToInt(key, 0);
        y[2] = byteToInt(key, 4);
        y[3] = byteToInt(key, 8);
        y[4] = byteToInt(key, 12);

        if (key.length == 32) {
            constants = gamma1;
            rotate = 16;
        } else {
            constants = gamma2;
        }

        y[11] = byteToInt(key, rotate);
        y[12] = byteToInt(key, rotate + 4);
        y[13] = byteToInt(key, rotate + 8);
        y[14] = byteToInt(key, rotate + 12);
        y[0] = byteToInt(constants, 0);
        y[5] = byteToInt(constants, 4);
        y[10] = byteToInt(constants, 8);
        y[15] = byteToInt(constants, 12);

        y[6] = byteToInt(IV, 0);
        y[7] = byteToInt(IV, 4);
        y[8] = y[9] = 0;

        initialised = true;
    }

    private void salsa20WordToByte(int[] input, byte[] output) {
        System.arraycopy(input, 0, x, 0, input.length);

        for (int i = 0; i < 10; i++) {
            x[4] ^= rotl((x[0] + x[12]), 7);
            x[8] ^= rotl((x[4] + x[0]), 9);
            x[12] ^= rotl((x[8] + x[4]), 13);
            x[0] ^= rotl((x[12] + x[8]), 18);
            x[9] ^= rotl((x[5] + x[1]), 7);
            x[13] ^= rotl((x[9] + x[5]), 9);
            x[1] ^= rotl((x[13] + x[9]), 13);
            x[5] ^= rotl((x[1] + x[13]), 18);
            x[14] ^= rotl((x[10] + x[6]), 7);
            x[2] ^= rotl((x[14] + x[10]), 9);
            x[6] ^= rotl((x[2] + x[14]), 13);
            x[10] ^= rotl((x[6] + x[2]), 18);
            x[3] ^= rotl((x[15] + x[11]), 7);
            x[7] ^= rotl((x[3] + x[15]), 9);
            x[11] ^= rotl((x[7] + x[3]), 13);
            x[15] ^= rotl((x[11] + x[7]), 18);
            x[1] ^= rotl((x[0] + x[3]), 7);
            x[2] ^= rotl((x[1] + x[0]), 9);
            x[3] ^= rotl((x[2] + x[1]), 13);
            x[0] ^= rotl((x[3] + x[2]), 18);
            x[6] ^= rotl((x[5] + x[4]), 7);
            x[7] ^= rotl((x[6] + x[5]), 9);
            x[4] ^= rotl((x[7] + x[6]), 13);
            x[5] ^= rotl((x[4] + x[7]), 18);
            x[11] ^= rotl((x[10] + x[9]), 7);
            x[8] ^= rotl((x[11] + x[10]), 9);
            x[9] ^= rotl((x[8] + x[11]), 13);
            x[10] ^= rotl((x[9] + x[8]), 18);
            x[12] ^= rotl((x[15] + x[14]), 7);
            x[13] ^= rotl((x[12] + x[15]), 9);
            x[14] ^= rotl((x[13] + x[12]), 13);
            x[15] ^= rotl((x[14] + x[13]), 18);
        }

        int rotate = 0;
        for (int i = 0; i < stateSize; i++) {
            intToByte(x[i] + input[i], output, rotate);
            rotate += 4;
        }

        for (int i = stateSize; i < x.length; i++) {
            intToByte(x[i], output, rotate);
            rotate += 4;
        }
    }

    private byte[] intToByte(int x, byte[] out, int off) {
        out[off] = (byte) x;
        out[off + 1] = (byte) (x >>> 8);
        out[off + 2] = (byte) (x >>> 16);
        out[off + 3] = (byte) (x >>> 24);
        return out;
    }

    private int rotl(int x, int y) {
        return (x << y) | (x >>> -y);
    }


    private int byteToInt(byte[] x, int rotate) {
        return ((x[rotate] & 255)) |
                ((x[rotate + 1] & 255) << 8) |
                ((x[rotate + 2] & 255) << 16) |
                (x[rotate + 3] << 24);
    }

    private void resetCounter() {
        cW0 = 0;
        cW1 = 0;
        cW2 = 0;
    }

    private boolean limitExceeded() {
        cW0++;
        if (cW0 == 0) {
            cW1++;
            if (cW1 == 0) {
                cW2++;
                return (cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
            }
        }

        return false;
    }

    private boolean limitExceeded(int len) {
        if (cW0 >= 0) {
            cW0 += len;
        } else {
            cW0 += len;
            if (cW0 >= 0) {
                cW1++;
                if (cW1 == 0) {
                    cW2++;
                    return (cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
                }
            }
        }

        return false;
    }

    public static void main(String[] args) throws Exception {
        byte[] iv = new byte[CryptoConstants.SYM_IV_SIZE];
        byte[] key = new byte[CryptoConstants.SYM_KEY_SIZE];
        StreamCipher eCipher = StreamCipherFactory.createCipher("Salsa20");
        StreamCipher dCipher = StreamCipherFactory.createCipher("Salsa20");
        eCipher.engineInitEncrypt(key, iv);
        dCipher.engineInitDecrypt(key, iv);
        long t = System.currentTimeMillis();
        System.out.println(key);
        System.out.println(iv);
        File file = new File("E:\\alalal\\gagaga.txt");

        if (file.exists()) {
            long length = file.length();
            byte[] needToEncode;
            byte[] encoded;
            byte[] decoded;
            try (FileReader reader = new FileReader("E:\\alalal\\gagaga.txt");
                 BufferedReader br = new BufferedReader(reader)) {


                String line;
                while ((line = br.readLine()) != null) {
                    needToEncode = line.getBytes();
                    encoded = eCipher.crypt(needToEncode, 0, needToEncode.length);
                    decoded = dCipher.crypt(encoded, 0, encoded.length);
                    String str = new String (decoded,"UTF-8");
                    System.out.println(str);
                }


            }

        }


    }
}



