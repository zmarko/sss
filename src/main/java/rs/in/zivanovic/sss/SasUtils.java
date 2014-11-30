/*
 * The MIT License
 *
 * Copyright 2014 Marko Zivanovic.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package rs.in.zivanovic.sss;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Utility methods for generating, transforming, encoding and decoding input data into format that we can do the math
 * with.
 */
public final class SasUtils {

    private static final Random RANDOM = new SecureRandom();
    private static final byte[] SIGNATURE = "SS".getBytes(StandardCharsets.UTF_8);

    /**
     * Encode any valid Unicode string to integer.
     *
     * @param str string to encode as integer.
     * @return integer representation of the secret string.
     */
    public static BigInteger encodeStringToInteger(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] res;
        if ((bytes[0] & 0b10000000) >> 7 == 1) {
            res = new byte[bytes.length + 1];
            res[0] = 0;
            System.arraycopy(bytes, 0, res, 1, bytes.length);
        } else {
            res = bytes;
        }
        BigInteger r = new BigInteger(res);
        assert r.compareTo(BigInteger.ZERO) > 0;
        return r;
    }

    /**
     * Decode integer encoded with {@link #encodeStringToInteger(java.lang.String) } back to Unicode string form.
     *
     * @param num integer to decode back to string.
     * @return decoded string.
     */
    @SuppressWarnings("empty-statement")
    public static String decodeIntegerToString(BigInteger num) {
        byte[] bytes = num.toByteArray();
        int count;
        for (count = 0; count < bytes.length && bytes[count] == 0; count++);
        byte[] trimmed = new byte[bytes.length - count];
        System.arraycopy(bytes, count, trimmed, 0, trimmed.length);
        return new String(trimmed, StandardCharsets.UTF_8);
    }

    /**
     * Generate first probable prime greater than the number specified.
     *
     * @param num lower bound for the generated probable prime
     * @return probable prime greater than the specified number
     */
    public static BigInteger generateFirstPrimeGreaterThan(BigInteger num) {
        return num.nextProbablePrime();
    }

    /**
     * Generate random probable prime guaranteed to be greater than the number specified.
     *
     * @param num lower bound for the generated probable prime
     * @return random probable prime greater than the specified number
     */
    public static BigInteger generateRandomPrimeGreaterThan(BigInteger num) {
        BigInteger res = BigInteger.ZERO;
        while (res.compareTo(num) <= 0) {
            res = BigInteger.probablePrime(num.bitLength(), RANDOM);
        }
        return res;
    }

    /**
     * Generate random number guaranteed to be less than the number specified.
     *
     * @param num upper bound of the generated random number
     * @return random number guaranteed to be less than the specified number
     */
    public static BigInteger generateRandomIntegerLessThan(BigInteger num) {
        BigInteger r = null;
        while (r == null || r.compareTo(num) >= 0) {
            r = new BigInteger(num.bitLength(), RANDOM);
        }
        return r;
    }

    /**
     * Generate random coefficients for the Shamir's Secret Sharing algorithm. First coefficient is filled with a known
     * value and the rest of the coefficients are randomly generated, keeping them less than the specified prime.
     *
     * @param n number of coefficients to generate
     * @param elementZero value of the first coefficient
     * @param prime upper bound for randomly generated coefficients
     * @return array of generated coefficients
     */
    public static BigInteger[] generateRandomCoefficients(int n, BigInteger elementZero, BigInteger prime) {
        BigInteger[] res = new BigInteger[n];
        res[0] = elementZero;
        for (int i = 1; i < n; i++) {
            res[i] = SasUtils.generateRandomIntegerLessThan(prime);
        }
        return res;
    }

    /**
     * Serialize secret share to binary message format. The message consists of the following fields:
     * <ul>
     * <li>header (ASCII string "SS")</li>
     * <li>single byte indicating the ordinal number of this specific share in the series</li>
     * <li>single integer (four bytes) indicating the length of the share data</li>
     * <li>variable number of bytes (see previous item) representing share data</li>
     * <li>single integer (four bytes) indicating the length of the prime data</li>
     * <li>variable number of bytes (see previous item) representing prime data</li>
     * </ul>
     *
     * @param share secret share to serialize
     * @return byte array representing serialized secret share
     */
    public static byte[] encodeToBinary(SecretShare share) {
        if (share.getN() < 0 || share.getN() > 255) {
            throw new IllegalArgumentException("Invalid share number, must be between 0 and 255");
        }

        byte[] shareData = share.getShare().toByteArray();
        byte[] primeData = share.getPrime().toByteArray();
        byte n = new Integer(share.getN()).byteValue();

        int len = 9 + SIGNATURE.length + shareData.length + primeData.length;

        ByteBuffer bb = ByteBuffer.allocate(len);
        bb.put(SIGNATURE);
        bb.put(n);
        bb.putInt(shareData.length);
        bb.put(shareData);
        bb.putInt(primeData.length);
        bb.put(primeData);

        assert bb.position() == bb.capacity();
        assert bb.hasArray();

        return bb.array();
    }

    /**
     * De-serialize secret share from binary message data. Serialization mechanism is detailed in {@link #encodeToBinary(rs.in.zivanovic.sss.SecretShare)
     * }
     *
     * @param data binary data to de-serialize
     * @return secret share data
     */
    public static SecretShare decodeFromBinary(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        try {
            byte[] signature = new byte[SIGNATURE.length];
            bb.get(signature);
            if (!Arrays.equals(SIGNATURE, signature)) {
                throw new IllegalArgumentException("signature missing");
            }
            byte n = bb.get();
            int shareDataLen = bb.getInt();
            byte[] shareData = new byte[shareDataLen];
            bb.get(shareData);
            int primeDataLen = bb.getInt();
            byte[] primeData = new byte[primeDataLen];
            bb.get(primeData);

            BigInteger share = new BigInteger(shareData);
            BigInteger prime = new BigInteger(primeData);
            if (share.compareTo(BigInteger.ZERO) <= 0) {
                throw new IllegalArgumentException("invalid share number");
            }
            if (prime.compareTo(BigInteger.ZERO) <= 0) {
                throw new IllegalArgumentException("invalid prime");
            }
            return new SecretShare(n, share, prime);
        } catch (BufferUnderflowException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private SasUtils() {
    }

}
