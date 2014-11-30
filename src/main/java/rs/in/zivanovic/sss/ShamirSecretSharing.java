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
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the Shamir's Secret Sharing algorithm. Both splitting the secret into shares and joining the shares
 * back into the secret are supported. Since arbitrary-precision integers are used, there is, effectively, no limit on
 * the length of the secret data.
 *
 */
public final class ShamirSecretSharing {

    /**
     * Split the secret into the specified total number of shares. Specified minimum threshold of shares will need to be
     * present in order to join them back into the secret. Polynomial coefficients and prime modulo will be randomly
     * chosen.
     *
     * @param secretString string to convert into number and split into shares
     * @param total number of shares to generate
     * @param threshold minimum number of shares required to successfully join back the secret
     * @return list of shares
     */
    public static List<SecretShare> split(String secretString, int total, int threshold) {
        BigInteger secret = SasUtils.encodeStringToInteger(secretString);
        return split(secret, total, threshold);
    }

    /**
     * Split the secret into the specified total number of shares. Specified minimum threshold of shares will need to be
     * present in order to join them back into the secret. Polynomial coefficients and prime modulo will be randomly
     * chosen.
     *
     * @param secret number to split into shares
     * @param total number of shares to generate
     * @param threshold minimum number of shares required to successfully join back the secret
     * @return list of shares
     */
    public static List<SecretShare> split(BigInteger secret, int total, int threshold) {
        BigInteger prime = SasUtils.generateFirstPrimeGreaterThan(secret);
        BigInteger[] coeffs = SasUtils.generateRandomCoefficients(total, secret, prime);
        return split(secret, coeffs, total, threshold, prime);
    }

    /**
     * Split the secret into the specified total number of shares. Specified minimum threshold of shares will need to be
     * present in order to join them back into the secret.
     *
     * @param secret number to split into shares
     * @param coefficients random coefficients of the underlying polynomial
     * @param total number of shares to generate
     * @param threshold minimum number of shares required to successfully join back the secret
     * @param prime to be used for finite field arithmetic
     * @return list of shares
     */
    public static List<SecretShare> split(BigInteger secret, BigInteger[] coefficients, int total, int threshold,
            BigInteger prime) {

        if (secret.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("secret must be positive integer");
        }

        if (prime.compareTo(secret) <= 0) {
            throw new IllegalArgumentException("prime must be greater than secret");
        }

        if (coefficients.length < threshold) {
            throw new IllegalArgumentException("not enough coefficients, need " + threshold + ", have " +
                    coefficients.length);
        }

        if (total < threshold) {
            throw new IllegalArgumentException("total number of shares must be greater than or equal threshold");
        }

        List<SecretShare> shares = new ArrayList<>();

        for (int i = 1; i <= total; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger v = coefficients[0];
            for (int c = 1; c < threshold; c++) {
                v = v.add(x.modPow(BigInteger.valueOf(c), prime).multiply(coefficients[c]).mod(prime)).mod(prime);
            }
            shares.add(new SecretShare(i, v, prime));
        }
        return shares;
    }

    /**
     * Join shares back into the secret.
     *
     * @param shares to join
     * @return secret string
     */
    public static String joinToUtf8String(List<SecretShare> shares) {
        return SasUtils.decodeIntegerToString(join(shares));
    }

    /**
     * Join shares back into the secret.
     *
     * @param shares to join
     * @return secret number
     */
    public static BigInteger join(List<SecretShare> shares) {
        if (!checkSamePrimes(shares)) {
            throw new IllegalArgumentException("shares not from the same series");
        }
        BigInteger res = BigInteger.ZERO;
        for (int i = 0; i < shares.size(); i++) {
            BigInteger n = BigInteger.ONE;
            BigInteger d = BigInteger.ONE;
            BigInteger prime = shares.get(i).getPrime();
            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    BigInteger sp = BigInteger.valueOf(shares.get(i).getN());
                    BigInteger np = BigInteger.valueOf(shares.get(j).getN());
                    n = n.multiply(np.negate()).mod(prime);
                    d = d.multiply(sp.subtract(np)).mod(prime);
                }
            }
            BigInteger v = shares.get(i).getShare();
            res = res.add(prime).add(v.multiply(n).multiply(d.modInverse(prime))).mod(prime);
        }
        return res;
    }

    /**
     * Verify if all shares have the same prime. If they do not, then they are not from the same series and cannot
     * possibly be joined.
     *
     * @param shares to check
     * @return true if all shares have the same prime, false if not.
     */
    private static boolean checkSamePrimes(List<SecretShare> shares) {
        boolean ret = true;
        BigInteger prime = null;
        for (SecretShare share : shares) {
            if (prime == null) {
                prime = share.getPrime();
            } else if (!prime.equals(share.getPrime())) {
                ret = false;
                break;
            }
        }
        return ret;
    }

    private ShamirSecretSharing() {
    }

}
