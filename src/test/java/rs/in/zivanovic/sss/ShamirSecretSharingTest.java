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
import java.util.*;
import static org.junit.Assert.*;
import org.junit.Test;

public class ShamirSecretSharingTest {

    private static final BigInteger[] TEST_COEFFICIENTS = new BigInteger[3];
    private static final BigInteger TEST_PRIME = BigInteger.valueOf(1613);
    private static final BigInteger TEST_SECRET = BigInteger.valueOf(1234);
    private static final List<SecretShare> SHARES;

    static {
        TEST_COEFFICIENTS[0] = TEST_SECRET;
        TEST_COEFFICIENTS[1] = BigInteger.valueOf(166);
        TEST_COEFFICIENTS[2] = BigInteger.valueOf(94);
        SHARES = ShamirSecretSharing.split(TEST_SECRET, TEST_COEFFICIENTS, 6, 3, TEST_PRIME);
    }

    @Test
    public void testSplit() {
        System.out.println("split");
        assertTrue(SHARES.get(0).getShare().compareTo(BigInteger.valueOf(1494)) == 0);
        assertTrue(SHARES.get(1).getShare().compareTo(BigInteger.valueOf(329)) == 0);
        assertTrue(SHARES.get(2).getShare().compareTo(BigInteger.valueOf(965)) == 0);
        assertTrue(SHARES.get(3).getShare().compareTo(BigInteger.valueOf(176)) == 0);
        assertTrue(SHARES.get(4).getShare().compareTo(BigInteger.valueOf(1188)) == 0);
        assertTrue(SHARES.get(5).getShare().compareTo(BigInteger.valueOf(775)) == 0);
    }

    @Test
    public void testJoinInsufficientShares() {
        System.out.println("joinInsufficientShares");
        List<SecretShare> shares = new ArrayList<>();
        shares.add(SHARES.get(0));
        shares.add(SHARES.get(5));
        BigInteger joined = ShamirSecretSharing.join(shares);
        assertTrue(joined.compareTo(TEST_SECRET) != 0);
    }

    @Test
    public void testJoinSufficientShares() {
        System.out.println("joinSufficientShares");
        List<SecretShare> shares = new ArrayList<>();
        shares.add(SHARES.get(3));
        shares.add(SHARES.get(5));
        shares.add(SHARES.get(1));
        BigInteger joined = ShamirSecretSharing.join(shares);
        assertTrue(joined.compareTo(TEST_SECRET) == 0);
    }

}
