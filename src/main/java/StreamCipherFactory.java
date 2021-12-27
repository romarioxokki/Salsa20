public class StreamCipherFactory {

    public static StreamCipher createCipher(String algorithm) {

        if ("Salsa20".equals(algorithm))
            return new Salsa20();
        else
            return null;
    }

}