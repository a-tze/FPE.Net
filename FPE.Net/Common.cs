/**
 * Format-Preserving Encryption
 * 
 * Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
 * Copyright (c) 2018 Matthias Hunstock (ported to .NET)
 * 
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Sutton Abinger licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
using System;
using System.Linq;
using System.Numerics;

namespace FPE.Net
{

    /**
     * Common functions used by FF1 and FF3.
     * 
     * @author Kai Johnson
     */
    internal static class Common
    {

        /**
         * NIST SP 800-38G Algorithm 1: NUM<sub>radix</sub>(X) - Converts a string
         * of numerals to an integer, valuing the numerals in decreasing order of
         * significance.
         * <p>
         * Prerequisite:<br>
         * Base, radix.
         * <p>
         * Input:<br>
         * Numeral string, X.
         * <p>
         * Output:<br>
         * Number, x.
         * 
         * @param X
         *            The string of numerals to convert to a number.
         * @param radix
         *            The base of the numerals such that 0 &lt;= X[i] &lt; radix for
         *            all i.
         * @return The number that the numeral string X represents in base
         *         <i>radix</i> when the numerals are valued in decreasing order of
         *         significance.
         * @throws NullReferenceException
         *             If X is null.
         * @throws Exception
         *             If X is empty or has more than
         *             {@value org.fpe4j.Constants#MAXLEN} elements; if
         *             radix is less than
         *             {@value org.fpe4j.Constants#MINRADIX} or greater
         *             than {@value org.fpe4j.Constants#MAXRADIX}; or if
         *             any numeral X[i] is outside the range [0..radix-1].
         */
        public static BigInteger num(int[] X, int radix)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null.");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception("The length of X is not within the permitted range of 1" + ".."
                        + Constants.MAXLEN + ": " + X.Length);
            // validate radix
            if (radix < Constants.MINRADIX || radix > Constants.MAXRADIX)
                throw new Exception($"Radix not within the permitted range of { Constants.MINRADIX }..{ Constants.MAXRADIX}: {radix}");

            // 1. Let x = 0.
            BigInteger x = BigInteger.Zero;

            // type conversion for readability
            BigInteger r = radix;

            // 2. For i from 1 to LEN(X)
            for (int i = 0; i < X.Length; i++)
            {
                // check the value of X[i]
                if (X[i] < 0 || X[i] >= radix)
                    throw new Exception($"X[{i}] is not within the range of values defined by the radix (0..{radix})");

                // let x = x * radix + X[i]

                x = BigInteger.Add(BigInteger.Multiply(x, r), X[i]);
            }

            // 3. Return x.
            return x;
        }

        /**
         * NIST SP 800-38G Algorithm 2: NUM(X) - Converts a string of bytes to an
         * integer, valuing the bytes as unsigned integers in decreasing order of
         * significance.
         * <p>
         * Input:<br>
         * Byte string, X, represented in bits.
         * <p>
         * Output:<br>
         * Integer, x.
         * <p>
         * Note that NIST SP 800-38G defines the algorithm in terms of bits, but we
         * have implemented it using an array of bytes as input.
         * 
         * @param X
         *            The string of bytes to convert to a number.
         * @return The integer that a byte string X represents when the bytes are
         *         valued in decreasing order of significance.
         * @throws NullReferenceException
         *             If X is null.
         * @throws Exception
         *             If X is empty or if X has more than
         *             {@value org.fpe4j.Constants#MAXLEN} elements.
         */
        public static BigInteger num(byte[] X)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null.");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception(
                        "The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.Length);

            // 1. Let x = 0.
            BigInteger x = BigInteger.Zero;

            // set value of radix for readability
            BigInteger r = 256;

            // 2. For i from 1 to LEN(X)
            for (int i = 0; i < X.Length; i++)
            {
                // let x = 2x + X[i]
                x = BigInteger.Add(
                    BigInteger.Multiply(x, r),
                    (X[i] & 0xFF));
                /*
                 * Note that the implementation is different than NIST SP 800-38G
                 * because we're valuing bytes rather than individual bits
                 */
            }

            /*
             * Instead of implementing the algorithm described in NIST SP 800-38G,
             * we could use the native conversion in the BigInteger class.
             * 
             * BigInteger x = new BigInteger(1, X)
             * 
             * However, we've kept the implementation as described in NIST SP
             * 800-38G for readability.
             */

            // 3. Return x.
            return x;
        }

        /**
         * NIST SP 800-38G Algorithm 3: STR<sup>m</sup><sub>radix</sub>(x) -
         * Converts an integer to an array of numerals of a given radix.
         * <p>
         * Prerequisites:<br>
         * Base, radix;<br>
         * String length, m.
         * <p>
         * Input:<br>
         * Integer, x, such that 0 &lt;= x &lt; radix<sup>m</sup>.
         * <p>
         * Output:<br>
         * Numeral string, X.
         * 
         * @param x
         *            The integer to convert to a string of numerals.
         * @param radix
         *            The base of the numerals such that 0 &lt;= X[i] &lt; radix for
         *            all i.
         * @param m
         *            The length of the string of numerals.
         * @return Given a nonnegative integer x less than radix<sup>m</sup>, the
         *         representation of x as a string of m numerals in base radix, in
         *         decreasing order of significance.
         * @throws NullReferenceException
         *             If x is null.
         * @throws Exception
         *             If m is not within the range
         *             [1..{@value org.fpe4j.Constants#MAXLEN}]; if
         *             radix is not within the range
         *             [{@value org.fpe4j.Constants#MINRADIX}..{@value org.fpe4j.Constants#MAXRADIX}];
         *             or if x is not within the range [0..radix<sup>m</sup>].
         */
        public static int[] str(BigInteger x, int radix, int m)
        {
            // validate m
            if (m < 1 || m > Constants.MAXLEN)
                throw new Exception(
                        "M is not within the permitted range of 1" + ".." + Constants.MAXLEN + ": " + m);

            // validate radix
            if (radix < Constants.MINRADIX || radix > Constants.MAXRADIX)
                throw new Exception("Radix not within the permitted range of " + Constants.MINRADIX + ".."
                        + Constants.MAXRADIX + ": " + radix);

            // type conversion for readability
            BigInteger r = radix;

            // validate x
            if (x == null)
                throw new NullReferenceException("x must not be null");
            if (x.CompareTo(BigInteger.Zero) < 0 ||
                x.CompareTo(BigInteger.Pow(r, m)) >= 0)
                throw new Exception("X is not within the permitted range of 0.." + BigInteger.Pow(r, m) + ": " + x);

            // allocate result array
            int[] X = new int[m];

            // 1. For i from 1 to m:
            for (int i = 1; i <= m; i++)
            {

                // i. X[m+1-i] = x mod radix;
                X[m - i] = (int)(x % r);

                // ii. x = floor(x/radix).
                x = x / r;
                /*
                 * BigInteger.divide() rounds down, so we don't need to apply the
                 * floor function
                 */
            }

            // 2. Return X.
            return X;
        }

        /**
         * NIST SP 800-38G Algorithm 4: REV(X) - Reverse a string of numerals.
         * <p>
         * Input:<br>
         * Numeral string, X.
         * <p>
         * Output:<br>
         * Numeral string, Y.
         * 
         * @param X
         *            The numeral string to reverse.
         * @return Given a numeral string, X, the numeral string that consists of
         *         the numerals of X in reverse order.
         * @throws NullReferenceException
         *             If X is null.
         */
        public static int[] rev(int[] X)
        {
            // validate x
            if (X == null)
                throw new NullReferenceException("X must not be null");

            int[] Y = new int[X.Length];

            // 1. For i from 1 to LEN(X)
            for (int i = 0; i < X.Length; i++)
            {

                // let Y[i] = X[LEN(X)+1-i]
                Y[i] = X[X.Length - i - 1];
                /*
                 * Note that NIST SP 800-38G assumes array indexes starting at 1
                 * instead of array indexes starting at 0.
                 */
            }

            // 2. Return Y[1..LEN(X)].
            return Y;
        }

        /**
         * NIST SP 800-38G Algorithm 5: REVB(X) - Reverse an array of bytes.
         * <p>
         * Input:<br>
         * Byte string, X, represented in bits.
         * <p>
         * Output:<br>
         * Byte string, Y, represented in bits.
         * <p>
         * Note that although NIST SP 800-38G refers to strings of individually
         * addressable bits, this is not a common feature of programming languages.
         * In this implementation, we use arrays of bytes to represent the data
         * type.
         * 
         * @param X
         *            The bit string (i.e. array of bytes) to reverse.
         * @return Given a byte string, X, the byte string that consists of the
         *         bytes of X in reverse order.
         * @throws NullReferenceException
         *             If X is null.
         */
        public static byte[] revb(byte[] X)
        {
            // validate x
            if (X == null)
                throw new NullReferenceException("X must not be null");

            byte[] Y = new byte[X.Length];

            // 1. For i from 0 to BYTELEN(X)-1 and j from 1 to 8,
            for (int i = 0; i < X.Length; i++)
            {
                // let Y[8i+j] = * X[8 * (BYTELEN(X)-1-i)+j].
                Y[i] = X[X.Length - i - 1];
                /*
                 * Note that the implementation is different than NIST SP 800-38G
                 * because we're copying bytes rather than individual bits
                 */
            }

            // 2. Return Y[1..8 * BYTELEN(X)].
            return Y;
        }

        /**
         * Returns an array of bytes whose values are X[i] ^ Y[i].
         * <p>
         * NIST SP 800-38G notation: X &oplus; Y
         * 
         * @param X
         *            The first bit string (i.e. array of bytes).
         * @param Y
         *            The second bit string (i.e. array of bytes).
         * @return The bitwise addition, modulo 2, of two bit strings of equal
         *         length.
         * @throws NullReferenceException
         *             If either X or Y is null.
         * @throws Exception
         *             if X or Y is empty; if X or Y has more than
         *             {@value org.fpe4j.Constants#MAXLEN} elements; or
         *             if X.Length != Y.Length.
         */
        public static byte[] xor(byte[] X, byte[] Y)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception(
                        "The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.Length);

            // validate Y
            if (Y == null)
                throw new NullReferenceException("Y must not be null");
            if (Y.Length < 1 || Y.Length > Constants.MAXLEN)
                throw new Exception(
                        "The length of Y is not within the permitted range of 1.." + Constants.MAXLEN + ": " + Y.Length);
            if (Y.Length != X.Length)
                throw new Exception("X and Y must be the same length. X: " + X.Length + " Y: " + Y.Length);

            // allocate result array
            byte[] Z = new byte[X.Length];

            // xor bytes
            for (int i = 0; i < X.Length; i++)
                Z[i] = (byte)(X[i] ^ Y[i]);

            return Z;
        }

        /**
         * Returns the base 2 logarithm of x.
         * <p>
         * We have renamed this function "log2(x)" to avoid confusion with the
         * natural log function.
         * <p>
         * NIST SP 800-38G describes the input as a "real" number, but only provides
         * integer values as input, so we have defined the input as an int to avoid
         * unnecessary type conversion.
         * <p>
         * NIST SP 800-38G notation: LOG(x)
         * 
         * @param x
         *            The real number &gt; 0.
         * @return The base 2 logarithm of the real number x &gt; 0.
         * @throws Exception
         *             If x is not greater than 0.
         */
        public static double log2(int x)
        {
            // validate x
            if (x <= 0)
                throw new Exception("x must be a positive integer");

            return Math.Log(x, 2);
        }

        /**
         * Returns the largest integer value that is less than or equal to x.
         * <p>
         * In NIST SP 800-38G, this function is used to round the result of integer
         * division. However, in Java, the result of integer division is rounded
         * down to an integer. To use the function on the result of integer
         * division, one of the integers must first be converted to a double to
         * produce a fractional result.
         * <p>
         * NIST SP 800-38G notation: &lfloor;x&rfloor;
         * 
         * @param x
         *            The real number.
         * @return The greatest integer that does not exceed the real number x.
         */
        public static int floor(double x)
        {
            return (int)Math.Floor(x);
        }

        /**
         * Alternate form of the floor function with an integer argument to trap
         * incorrect usage.
         * 
         * @param x
         *            An integer.
         * @return Throws an Exception.
         */
        public static int floor(int x)
        {
            throw new Exception("x must be a double");
        }

        /**
         * Returns the smallest integer value that is greater than or equal to x.
         * <p>
         * In NIST SP 800-38G, this function is used to round the result of integer
         * division. However, in Java, the result of integer division is rounded
         * down to an integer. To use the function on the result of integer
         * division, one of the integers must first be converted to a double to
         * produce a fractional result.
         * <p>
         * NIST SP 800-38G notation: &lceil;x&rceil;
         * 
         * @param x
         *            The real number.
         * @return The least integer that is not less than the real number x.
         */
        public static int ceiling(double x)
        {
            return (int)Math.Ceiling(x);
        }

        /**
         * Alternate form of the ceiling function with an integer argument to trap
         * incorrect usage.
         * 
         * @param x
         *            An integer.
         * @return Throws an Exception.
         */
        public static int ceiling(int x)
        {
            throw new Exception("x must be a double");
        }

        /**
         * Given a real number x and a positive integer m, returns the remainder of
         * x modulo m, denoted by x mod m, which is x - m * floor(x/m).
         * <p>
         * NIST SP 800-38G describes the input as a "real" number, but provides only
         * integer values as input. We have defined the input as an int to avoid
         * unnecessary type conversion.
         * <p>
         * NIST SP 800-38G Notation: MOD(x)
         * 
         * @param x
         *            The "real" number (defined as an int to avoid unnecessary type
         *            conversion).
         * @param m
         *            The modulus.
         * @return The nonnegative remainder of the integer x modulo the positive
         *         integer m.
         * @throws ArithmeticException
         *             If m is less than 1.
         */
        public static int mod(int x, int m)
        {
            // validate m
            if (m < 1)
                throw new ArithmeticException("m must be a positive integer");

            // x - m * floor(x / m);
            return x - m * floor(x / (double)m);
        }

        /**
         * Given a real number x and a positive integer m, returns the remainder of
         * x modulo m, denoted by x mod m, which is x - m * floor(x/m).
         * <p>
         * NIST SP 800-38G describes the input as a "real" number, but provides only
         * integer values as input. We have defined the input as a BigInteger to
         * avoid unnecessary type conversion.
         * <p>
         * NIST SP 800-38G Notation: MOD(x)
         * 
         * @param x
         *            The "real" number (defined as a BigInteger to avoid
         *            unnecessary type conversion).
         * @param m
         *            The modulus.
         * @return The nonnegative remainder of the integer x modulo the positive
         *         integer m.
         * @throws ArithmeticException
         *             If m is less than 1.
         */
        public static BigInteger mod(BigInteger x, BigInteger m)
        {
            // validate m
            if (m.Sign < 0)
                throw new ArithmeticException("m must be a positive integer");

            // return x - m * floor(x / m);
            /*
             * return x.subtract(m.multiply(new BigDecimal(x).divide(new
             * BigDecimal(m), RoundingMode.FLOOR).toBigInteger()));
             * 
             * This literal implementation of the pseudocode from NIST SP 800-38G is
             * provided only for comparison to the BigInteger.mod() method.
             */
            BigInteger rem = x % m;

            return rem >= 0 ? rem : rem + m;
        }

        /**
         * Expands x into an array of bytes of length s.
         * <p>
         * NIST SP 800-38G notation: [x]<sup>s</sup>
         * 
         * @param x
         *            The integer to convert to an array of bytes.
         * @param s
         *            The length of the output in bytes.
         * @return Given a nonnegative integer x less than 256<sup>s</sup> , the
         *         representation of x as a string of s bytes.
         * @throws Exception
         *             If s is not within the range
         *             [1..{@value org.fpe4j.Constants#MAXLEN}]; if x is
         *             negative; or if x is greater than 256<sup>s</sup>.
         */
        public static byte[] bytestring(int x, int s)
        {
            // validate s
            if (s < 1 || s > Constants.MAXLEN)
                throw new Exception(
                        "s is not within the permitted range of 1.." + Constants.MAXLEN + ": " + s);

            // validate x
            if (x < 0)
                throw new Exception("x must be nonnegative");
            if (x >= Math.Pow(256, s))
                throw new Exception("x must be less than 256^s (" + x + " >= " + Math.Pow(256, s) + ")");

            byte[] str = new byte[s];

            // traverse s in reverse order, but stop if x is zero
            for (int i = s - 1; i >= 0 && x > 0; i--)
            {

                // copy the least significant byte of x
                str[i] = (byte)(x & 0xFF);

                // shift x to get the next byte
                x = x >> 8;
            }

            return str;
        }

        /**
         * Expands x into an array of bytes of length s.
         * <p>
         * NIST SP 800-38G notation: [x]<sup>s</sup>
         * 
         * @param x
         *            The integer to convert to an array of bytes.
         * @param s
         *            The length of the output in bytes.
         * @return Given a nonnegative integer x less than 256<sup>s</sup> , the
         *         representation of x as a string of s bytes.
         * @throws Exception
         *             If s is not within the range
         *             [1..{@value org.fpe4j.Constants#MAXLEN}]; if x is
         *             negative; or if x is greater than 256<sup>s</sup>.
         */
        public static byte[] bytestring(BigInteger x, int s)
        {
            // validate s
            if (s < 1)
                throw new Exception("s must be a positive integer");

            // validate x
            if (x.CompareTo(BigInteger.Zero) < 0)
                throw new Exception("x must be nonnegative");
            if (x.CompareTo(BigInteger.Pow(256, s)) >= 0)
                throw new Exception($"x must be less than 256^s ({s}) (" + x + " >= " + BigInteger.Pow(256, s) + ")");

            byte[] str = new byte[s];

            // convert x to an array of bytes
            byte[] xBytes = x.ToByteArray().Reverse().ToArray();

            // copy the bytes to the rightmost portion of the result
            Array.Copy(
                xBytes, Math.Max(xBytes.Length - s, 0),
                str, Math.Max(s - xBytes.Length, 0),
                Math.Min(xBytes.Length, s));

            return str;
        }

        /**
         * Returns an array of bits of length s filled with either 0s or 1s.
         * <p>
         * Note that although NIST SP 800-38G refers to strings of individually
         * addressable bits, this is not a common feature of programming languages.
         * In this implementation, we use arrays of bytes to represent the data
         * type.
         * <p>
         * The implementations of FF1 and FF3 sometimes use inline constants in
         * place of this bitstring function.
         * <p>
         * NIST SP 800-38G notation: 0<sup>s</sup> or 1<sup>s</sup>
         * 
         * @param bit
         *            The bit value with which to fill the output; false = 0, true =
         *            1
         * @param s
         *            The length of the output in bits (not bytes!)
         * @return The bit string that consists of s consecutive 'bit' bits.
         * @throws Exception
         *             If s &lt;= 0 or if s is not a multiple of 8.
         */
        public static byte[] bitstring(bool bit, int s)
        {
            // validate s
            if (s < 1)
                throw new Exception("s must be a positive integer");
            if (s % 8 != 0)
                throw new Exception("s must be a multiple of 8: " + s);

            byte[] str = new byte[s / 8];
            for (int i = 0; i < str.Length; i++)
            {
                str[i] = bit ? (byte)0xFF : (byte)0x00;
            }

            return str;
        }

        /**
         * Concatenates two arrays of integers.
         * <p>
         * NIST SP 800-38G notation: X || Y
         * 
         * @param X
         *            The first numeral string.
         * @param Y
         *            The second numeral string.
         * @return The concatenation of numeral strings X and Y.
         * @throws NullReferenceException
         *             If X or Y is null.
         */
        public static int[] concatenate(int[] X, int[] Y)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");

            // validate Y
            if (Y == null)
                throw new NullReferenceException("Y must not be null");

            int[] Z = new int[X.Length + Y.Length];

            Array.Copy(X, 0, Z, 0, X.Length);
            Array.Copy(Y, 0, Z, X.Length, Y.Length);

            return Z;
        }

        /**
         * Concatenates two arrays of bytes
         * <p>
         * NIST SP 800-38G notation: X || Y
         * 
         * @param X
         *            The first numeral string.
         * @param Y
         *            The second numeral string.
         * @return The concatenation of numeral strings X and Y.
         * @throws NullReferenceException
         *             If X or Y is null.
         */
        public static byte[] concatenate(byte[] X, byte[] Y)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");

            // validate Y
            if (Y == null)
                throw new NullReferenceException("Y must not be null");

            byte[] Z = new byte[X.Length + Y.Length];

            Array.Copy(X, 0, Z, 0, X.Length);
            Array.Copy(Y, 0, Z, X.Length, Y.Length);

            return Z;
        }

        /**
         * Converts an array of integers to a string, with spaces separating the
         * integer values.
         * 
         * @param X
         *            The array of integers.
         * @return The string with spaces separating the elements of X.
         * @throws NullReferenceException
         *             If X is null.
         */
        public static string intArrayToString(int[] X)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");

            return string.Join(" ", X);
        }

        /**
         * Converts an array of bytes to a string, treating the bytes as unsigned
         * integers, with commas and spaces separating the byte values.
         * 
         * @param X
         *            The array of bytes.
         * @return The string with commas and spaces separating the elements of X
         *         interpreted as unsigned values.
         * @throws NullReferenceException
         *             If X is null.
         */
        public static string unsignedByteArrayToString(byte[] X)
        {
            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");

            return "[" + string.Join(", ", X) + "]";
        }

        /**
         * String conversion table for byteArrayToHexString().
         */
        private static readonly string[] HEX_STRINGS = new string[] { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A",
            "0B", "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C",
            "1D", "1E", "1F", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E",
            "2F", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", "40",
            "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52",
            "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "60", "61", "62", "63", "64",
            "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76",
            "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83", "84", "85", "86", "87", "88",
            "89", "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A",
            "9B", "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC",
            "AD", "AE", "AF", "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE",
            "BF", "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", "D0",
            "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2",
            "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4",
            "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF" };

        /**
         * Converts an array of bytes to a string representing the hexadecimal value
         * of the bytes.
         * 
         * @param X
         *            The array of bytes.
         * @return The string representing the hexadecimal values of the bytes.
         * @throws NullReferenceException
         *             If X is null.
         */
        public static string byteArrayToHexString(byte[] X)
        {
            // validate X
            if (X == null)
            {
                throw new NullReferenceException("X must not be null");
            }

            return string.Join("", X.Select(x => HEX_STRINGS[x & 0xFF]));
        }
    }

}
