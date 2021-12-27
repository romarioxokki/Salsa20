public interface StreamCipher {
    public void engineInitEncrypt(byte[] key, byte[] iv);

    public void engineInitDecrypt(byte[] key, byte[] iv);

    public void crypt(byte[] in, int inOffset, int length, byte[] out, int outOffset);

    public byte[] crypt(byte[] data, int position, int length);


}