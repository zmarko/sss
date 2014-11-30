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
import static org.junit.Assert.*;
import org.junit.Test;

public class SasUtilsTest {

    private static final String s1 = "Hello World!";

    public SasUtilsTest() {
    }

    @Test
    public void testGenerateFirstPrimeGreaterThan() {
        System.out.println("generateFirstPrimeGreaterThan");
        BigInteger si1 = SasUtils.encodeStringToInteger(s1);
        BigInteger p1 = SasUtils.generateFirstPrimeGreaterThan(si1);
        assertTrue(p1.compareTo(si1) > 0);
    }

    @Test
    public void testGenerateRandomPrimeGreaterThan() {
        System.out.println("generateRandomPrimeGreaterThan");
        BigInteger si1 = SasUtils.encodeStringToInteger(s1);
        BigInteger p1 = SasUtils.generateRandomPrimeGreaterThan(si1);
        assertTrue(p1.compareTo(si1) > 0);
    }

    @Test
    public void testGenerateRandomIntegerLessThan() {
        System.out.println("generateRandomIntegerLessThan");
        BigInteger i = BigInteger.valueOf(100);
        BigInteger r = SasUtils.generateRandomIntegerLessThan(i);
        assertTrue(r.compareTo(i) < 0);
        i = BigInteger.valueOf(100_000_000);
        r = SasUtils.generateRandomIntegerLessThan(i);
        assertTrue(r.compareTo(i) < 0);
    }

    @Test
    public void testBinaryCodec() {
        System.out.println("binaryCodec");
        SecretShare src = new SecretShare(3, new BigInteger("100"), new BigInteger("200"));
        byte[] data = SasUtils.encodeToBinary(src);
        SecretShare dst = SasUtils.decodeFromBinary(data);
        assertTrue(src.equals(dst));
    }

    @Test
    public void testSecretCodec() {
        System.out.println("secretCodec");
        BigInteger bi = SasUtils.encodeStringToInteger(s1);
        String d = SasUtils.decodeIntegerToString(bi);
        assertTrue(s1.equals(d));
    }

    @Test(expected = java.lang.IllegalArgumentException.class)
    public void testDecodeEmptyMessage() {
        System.out.println("decodeEmptyMessage");
        byte[] b = new byte[0];
        SecretShare ss = SasUtils.decodeFromBinary(b);
    }

    @Test(expected = java.lang.IllegalArgumentException.class)
    public void testDecodePartialMessage() {
        System.out.println("decodePartialMessage");
        SecretShare src = new SecretShare(3, new BigInteger("100"), new BigInteger("200"));
        byte[] buff = SasUtils.encodeToBinary(src);
        byte[] partial = new byte[buff.length / 2];
        System.arraycopy(buff, 0, partial, 0, partial.length);
        SecretShare ss = SasUtils.decodeFromBinary(partial);
    }

    @Test(expected = java.lang.IllegalArgumentException.class)
    public void testDecodeDamagedHeaderMessage() {
        System.out.println("decodeDamagedHeader");
        SecretShare src = new SecretShare(3, new BigInteger("100"), new BigInteger("200"));
        byte[] buff = SasUtils.encodeToBinary(src);
        buff[0] = 'X';
        SecretShare ss = SasUtils.decodeFromBinary(buff);
    }

}
