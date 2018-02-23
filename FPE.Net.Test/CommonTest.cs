/**
 * Format-Preserving Encryption
 * 
 * Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;

namespace FPE.Net.Test
{
    /**
     * Unit test cases for the Common class.
     * 
     * @author Kai Johnson
     *
     */
    [TestClass]
    public class CommonTest
    {

        [TestMethod]
        public void TestNumIntArrayInt()
        {
            // example from NIST SP 800-38G
            int[] X1 = { 0, 0, 0, 1, 1, 0, 1, 0 };
            Assert.AreEqual(Common.num(X1, 5).CompareTo(755), 0);

            // null input
            try
            {
                Common.num(null, 10);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // input array too short
            try
            {
                int[] X = { };
                Common.num(X, 10);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // input array too long
            try
            {
                int[] X = new int[Constants.MAXLEN + 1];
                Common.num(X, 10);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // radix too small
            try
            {
                int[] X = { 0, 1, 2, 3, 4, 5 };
                Common.num(X, 1);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // radix too large
            try
            {
                int[] X = { 0, 1, 2, 3, 4, 5 };
                Common.num(X, 65537);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // values outside the range of the radix
            try
            {
                int[] X = { 0, 1, 2, 3, 4, 5 };
                Common.num(X, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // negative values
            try
            {
                int[] X = { 0, 1, -2, 3, 4, 5 };
                Common.num(X, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // byte value
            int[] X2 = { 1, 1, 1, 1, 1, 1, 1, 1 };
            Assert.AreEqual(Common.num(X2, 2).CompareTo(255), 0);

            // short value
            int[] X3 = { 15, 15, 15, 15 };
            Assert.AreEqual(Common.num(X3, 16).CompareTo(65535), 0);

            // int value
            int[] X4 = { 127, 255, 255, 255 };
            Assert.AreEqual(Common.num(X4, 256).CompareTo(Int32.MaxValue), 0);

            // long value
            int[] X5 = { 255, 255, 255, 255 };
            Assert.AreEqual(Common.num(X5, 256).CompareTo(4294967295L), 0);

            // yotta
            int[] X6 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            Assert.AreEqual(Common.num(X6, 256), new BigInteger(Math.Pow(2, 80)));
        }

        [TestMethod]
        public void testNumByteArray()
        {
            // null input
            try
            {
                byte[] X = null;
                Common.num(X);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // input array too short
            try
            {
                byte[] X = { };
                Common.num(X);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // input array too long
            try
            {
                byte[] X = new byte[Constants.MAXLEN + 1];
                Common.num(X);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // one byte values
            byte[] X1 = { (byte)0x00 };
            Assert.AreEqual(0, Common.num(X1));
            byte[] X2 = { (byte)0x01 };
            Assert.AreEqual(1, Common.num(X2));
            byte[] X3 = { (byte)0x80 };
            Assert.AreEqual(128, Common.num(X3));
            byte[] X4 = { (byte)0xFF };
            Assert.AreEqual(255, Common.num(X4));

            // two byte values
            byte[] X5 = { (byte)0x00, (byte)0x00 };
            Assert.AreEqual(0, Common.num(X5));
            byte[] X6 = { (byte)0x00, (byte)0x01 };
            Assert.AreEqual(1, Common.num(X6));
            byte[] X7 = { (byte)0x80, (byte)0x00 };
            Assert.AreEqual(32768, Common.num(X7));
            byte[] X8 = { (byte)0xFF, (byte)0xFF };
            Assert.AreEqual(65535, Common.num(X8));

            // four byte values
            byte[] X9 = { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
            Assert.AreEqual(0, Common.num(X9));
            byte[] X10 = { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01 };
            Assert.AreEqual(1, Common.num(X10));
            byte[] X11 = { (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00 };
            Assert.AreEqual(2147483648L, Common.num(X11));
            byte[] X12 = { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
            Assert.AreEqual(4294967295L, Common.num(X12));

            // yotta
            byte[] X13 = { (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
            Assert.AreEqual(new BigInteger(Math.Pow(2, 80)), Common.num(X13));
        }

        [TestMethod]
        public void testStr()
        {
            // example from NIST SP 800-38G
            int[] expected1 = { 0, 3, 10, 7 };
            CollectionAssert.AreEquivalent(expected1, Common.str(559, 12, 4));

            // m is too small
            try
            {
                Common.str(BigInteger.One, 10, 0);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // m is too small
            try
            {
                Common.str(BigInteger.One, 10, Constants.MAXLEN + 1);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // radix is too small
            try
            {
                Common.str(BigInteger.One, 1, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // radix is too large
            try
            {
                Common.str(BigInteger.One, 65537, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // X is negative
            try
            {
                Common.str(BigInteger.MinusOne, 10, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // X is too large
            try
            {
                Common.str(new BigInteger(Math.Pow(10, 4)), 10, 4);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // byte value
            int[] X2 = { 1, 1, 1, 1, 1, 1, 1, 1 };
            CollectionAssert.AreEquivalent(X2, Common.str(255, 2, 8));

            // short value
            int[] X3 = { 15, 15, 15, 15 };
            CollectionAssert.AreEquivalent(X3, Common.str(65535, 16, 4));

            // int value
            int[] X4 = { 127, 255, 255, 255 };
            CollectionAssert.AreEquivalent(X4, Common.str(Int32.MaxValue, 256, 4));

            // long value
            int[] X5 = { 255, 255, 255, 255 };
            CollectionAssert.AreEquivalent(X5, Common.str(4294967295L, 256, 4));

            // yotta
            int[] X6 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            CollectionAssert.AreEquivalent(X6, Common.str(new BigInteger(Math.Pow(2, 80)), 256, 11));
        }

        [TestMethod]
        public void testRev()
        {
            // example from NIST SP 800-38G
            int[] X1 = { 1, 3, 5, 7, 9 };
            int[] Y1 = { 9, 7, 5, 3, 1 };
            CollectionAssert.AreEquivalent(Y1, Common.rev(X1));

            // null input
            try
            {
                Common.rev(null);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // empty array
            int[] X2 = { };
            int[] Y2 = { };
            CollectionAssert.AreEquivalent(Y2, Common.rev(X2));

            // one element
            int[] X3 = { 5 };
            int[] Y3 = { 5 };
            CollectionAssert.AreEquivalent(Y3, Common.rev(X3));

            // many elements
            int[] X4 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            int[] Y4 = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
                6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
            CollectionAssert.AreEquivalent(Y4, Common.rev(X4));
        }

        [TestMethod]
        public void testRevb()
        {
            // example from NIST SP 800-38G
            byte[] X1 = { (byte)1, (byte)2, (byte)3 };
            byte[] Y1 = { (byte)3, (byte)2, (byte)1 };
            CollectionAssert.AreEquivalent(Y1, Common.revb(X1));

            // null input
            try
            {
                Common.revb(null);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty array
            byte[] X2 = { };
            byte[] Y2 = { };
            CollectionAssert.AreEquivalent(Y2, Common.revb(X2));

            // one element
            byte[] X3 = { 5 };
            byte[] Y3 = { 5 };
            CollectionAssert.AreEquivalent(Y3, Common.revb(X3));

            // many elements
            byte[] X4 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] Y4 = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
                6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
            CollectionAssert.AreEquivalent(Y4, Common.revb(X4));
        }

        [TestMethod]
        public void testXor()
        {
            // example from NIST SP 800-38G
            byte[] X1 = { (byte)0x13 };
            byte[] Y1 = { (byte)0x15 };
            byte[] Z1 = { (byte)0x06 };
            CollectionAssert.AreEquivalent(Z1, Common.xor(X1, Y1));

            // null input
            try
            {
                byte[] X = null;
                byte[] Y = { (byte)0xA5 };
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                byte[] X = { (byte)0x0F };
                byte[] Y = null;
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // mismatched length
            try
            {
                byte[] X = { (byte)0x0F, (byte)0xF0 };
                byte[] Y = { (byte)0xA5 };
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // empty arrays
            try
            {
                byte[] X = { };
                byte[] Y = { (byte)0xA5 };
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception)
            {
            }
            try
            {
                byte[] X = { (byte)0x0F };
                byte[] Y = { };
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // arrays too long
            try
            {
                byte[] X = new byte[Constants.MAXLEN + 1];
                byte[] Y = { (byte)0xA5 };
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception)
            {
            }
            try
            {
                byte[] X = { (byte)0x0F };
                byte[] Y = new byte[Constants.MAXLEN + 1];
                Common.xor(X, Y);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // one element
            byte[] X2 = { (byte)0x0F };
            byte[] Y2 = { (byte)0xA5 };
            byte[] Z2 = { (byte)0xAA };
            CollectionAssert.AreEquivalent(Z2, Common.xor(X2, Y2));

            // many elements
            byte[] X3 = { (byte)0x0F, (byte)0xF0, (byte)0xFF, (byte)0x00 };
            byte[] Y3 = { (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5 };
            byte[] Z3 = { (byte)0xAA, (byte)0x55, (byte)0x5A, (byte)0xA5 };
            CollectionAssert.AreEquivalent(Z3, Common.xor(X3, Y3));
        }

        [TestMethod]
        public void testLog2()
        {
            // examples from NIST SP 800-38G
            Assert.AreEqual(Common.log2(64), 6);
            Assert.AreEqual(Common.log2(10), Math.Log(10) / Math.Log(2));

            // negative
            try
            {
                Common.log2(-1);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // zero
            try
            {
                Common.log2(0);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // integer result
            Assert.AreEqual(Common.log2(1024), 10);

            // real result
            Assert.IsTrue(Common.log2(1023) < 10);
            Assert.IsTrue(Common.log2(1025) > 10);
        }

        [TestMethod]
        public void testFloor()
        {
            // examples from NIST SP 800-38G
            Assert.AreEqual(2, Common.floor(2.1));
            Assert.AreEqual(4, Common.floor((double)4));

            // correct usage
            Assert.AreEqual(2, Common.floor(7 / (double)3));
            Assert.AreEqual(2, Common.floor(7 / 3.0));

            // incorrect usage
            try
            {
                Assert.AreEqual(2, Common.floor(7 / 3));
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // native integer division
            Assert.AreEqual(2, 7 / 3);
        }

        [TestMethod]
        public void testCeiling()
        {
            // examples from NIST SP 800-38G
            Assert.AreEqual(3, Common.ceiling(2.1));
            Assert.AreEqual(4, Common.ceiling((double)4));

            // correct usage
            Assert.AreEqual(3, Common.ceiling(7 / (double)3));
            Assert.AreEqual(3, Common.ceiling(7 / 3.0));

            // incorrect usage
            try
            {
                Assert.AreEqual(3, Common.ceiling(7 / 3));
                Assert.Fail();
            }
            catch (Exception)
            {
            }
        }

        [TestMethod]
        public void testModIntInt()
        {
            // examples from NIST SP 800-38G
            Assert.AreEqual(4, Common.mod(-3, 7));
            Assert.AreEqual(6, Common.mod(13, 7));

            // negative modulus
            /*
             * Note that Math.floorMod() permits negative moduli where NIST SP
             * 800-38G does not.
             */
            try
            {
                Common.mod(13, -7);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // zero modulus
            try
            {
                Common.mod(13, 0);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

        }

        [TestMethod]
        public void testModBigIntegerBigInteger()
        {
            // examples from NIST SP 800-38G
            Assert.AreEqual(Common.mod(-3, 7), 4);
            Assert.AreEqual(Common.mod(13, 7), 6);

            // equivalence to BigInteger.mod()

            // NOTE: in .NET, BigInteger behaves differently,
            // therefore the negative test is useless
            //Assert.AreEqual(new BigInteger(-3) % 7, 4);
            Assert.AreEqual(new BigInteger(13) % 7, 6);

            // negative modulus
            try
            {
                Common.mod(13, -7);
                Assert.Fail();
            }
            catch (Exception)
            {
            }
            try
            {
                var temp = new BigInteger(13) % -7;
            }
            catch (Exception)
            {
            }

            // zero modulus
            try
            {
                Common.mod(13, BigInteger.Zero);
                Assert.Fail();
            }
            catch (Exception)
            {
            }
            try
            {
                var temp = new BigInteger(13) % BigInteger.Zero;
                Assert.Fail();
            }
            catch (Exception)
            {
            }

        }

        [TestMethod]
        public void testBytestringIntInt()
        {
            // example from NIST SP 800-38G
            byte[] expected1 = { (byte)0x01 };
            CollectionAssert.AreEquivalent(expected1, Common.bytestring(1, 1));

            // s too small
            try
            {
                Common.bytestring(1, 0);
            }
            catch (Exception)
            {
            }

            // s too big
            try
            {
                Common.bytestring(1, Constants.MAXLEN + 1);
            }
            catch (Exception)
            {
            }

            // x too small
            try
            {
                Common.bytestring(-1, 1);
            }
            catch (Exception)
            {
            }

            // one byte value
            byte[] expected2 = { (byte)0xFF };
            CollectionAssert.AreEquivalent(expected2, Common.bytestring(255, 1));

            // overflow one byte
            try
            {
                Common.bytestring(256, 1);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // two byte values
            byte[] expected4 = { (byte)0x00, (byte)0x01 };
            CollectionAssert.AreEquivalent(expected4, Common.bytestring(1, 2));

            byte[] expected5 = { (byte)0xFF, (byte)0xFF };
            CollectionAssert.AreEquivalent(expected5, Common.bytestring(65535, 2));

            // overflow two bytes
            try
            {
                Common.bytestring(65536, 2);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // extension to 16 bytes
            byte[] expected7 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01 };
            CollectionAssert.AreEquivalent(expected7, Common.bytestring(1, 16));

            byte[] expected8 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7F, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF };
            CollectionAssert.AreEquivalent(expected8, Common.bytestring(Int32.MaxValue, 16));
        }

        [TestMethod]
        public void testBytestringBigIntegerInt()
        {
            // example from NIST SP 800-38G
            byte[] expected1 = { (byte)0x01 };
            CollectionAssert.AreEquivalent(expected1, Common.bytestring(BigInteger.One, 1));

            // s too small
            try
            {
                Common.bytestring(BigInteger.One, 0);
            }
            catch (Exception)
            {
            }

            // x too small
            try
            {
                Common.bytestring(BigInteger.MinusOne, 1);
            }
            catch (Exception)
            {
            }

            // one byte value
            byte[] expected2 = { (byte)0xFF };
            CollectionAssert.AreEquivalent(expected2, Common.bytestring(255, 1));

            // overflow one byte
            try
            {
                Common.bytestring(256, 1);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // two byte values
            byte[] expected4 = { (byte)0x00, (byte)0x01 };
            CollectionAssert.AreEquivalent(expected4, Common.bytestring(BigInteger.One, 2));

            byte[] expected5 = { (byte)0xFF, (byte)0xFF };
            CollectionAssert.AreEquivalent(expected5, Common.bytestring(65535, 2));

            // overflow two bytes
            try
            {
                Common.bytestring(65536, 2);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            // extension to 16 byte values
            byte[] expected7 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01 };
            CollectionAssert.AreEquivalent(expected7, Common.bytestring(BigInteger.One, 16));

            byte[] expected8 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7F, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF };
            CollectionAssert.AreEquivalent(expected8, Common.bytestring(Int32.MaxValue, 16));
        }

        [TestMethod]
        public void testBitstring()
        {
            // example from NIST SP 800-38G
            byte[] expected1 = { (byte)0 };
            CollectionAssert.AreEquivalent(expected1, Common.bitstring(false, 8));

            // s is negative
            try
            {
                Common.bitstring(false, -8);
            }
            catch (Exception)
            {
            }

            // s is not a multiple of 8
            try
            {
                Common.bitstring(false, 4);
            }
            catch (Exception)
            {
            }

            // two byte values
            byte[] expected2 = { (byte)0, (byte)0 };
            CollectionAssert.AreEquivalent(expected2, Common.bitstring(false, 16));
            byte[] expected3 = { (byte)0xFF, (byte)0xFF };
            CollectionAssert.AreEquivalent(expected3, Common.bitstring(true, 16));

            // 16 byte values
            byte[] expected4 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            CollectionAssert.AreEquivalent(expected4, Common.bitstring(false, 128));
            byte[] expected5 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF };
            CollectionAssert.AreEquivalent(expected5, Common.bitstring(true, 128));
        }

        [TestMethod]
        public void testConcatenateIntArrayIntArray()
        {
            // example from NIST SP 800-38G
            int[] X1 = { 3, 1 };
            int[] Y1 = { 31, 8, 10 };
            int[] Z1 = { 3, 1, 31, 8, 10 };
            CollectionAssert.AreEquivalent(Z1, Common.concatenate(X1, Y1));

            // null input
            try
            {
                int[] X = { 1, 2, 3 };
                Common.concatenate(X, null);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                int[] Y = { 4, 5, 6 };
                Common.concatenate(null, Y);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty input
            int[] X2 = { 1, 2, 3 };
            int[] Y2 = { };
            int[] Z2 = { 1, 2, 3 };
            CollectionAssert.AreEquivalent(Z2, Common.concatenate(X2, Y2));
            int[] X3 = { };
            int[] Y3 = { 4, 5, 6 };
            int[] Z3 = { 4, 5, 6 };
            CollectionAssert.AreEquivalent(Z3, Common.concatenate(X3, Y3));
        }

        [TestMethod]
        public void testConcatenateByteArrayByteArray()
        {
            // example from NIST SP 800-38G
            byte[] X1 = { 3, 1 };
            byte[] Y1 = { 31, 8, 10 };
            byte[] Z1 = { 3, 1, 31, 8, 10 };
            CollectionAssert.AreEquivalent(Z1, Common.concatenate(X1, Y1));

            // null input
            try
            {
                byte[] X = { 1, 2, 3 };
                Common.concatenate(X, null);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                byte[] Y = { 4, 5, 6 };
                Common.concatenate(null, Y);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty input
            byte[] X2 = { 1, 2, 3 };
            byte[] Y2 = { };
            byte[] Z2 = { 1, 2, 3 };
            CollectionAssert.AreEquivalent(Z2, Common.concatenate(X2, Y2));
            byte[] X3 = { };
            byte[] Y3 = { 4, 5, 6 };
            byte[] Z3 = { 4, 5, 6 };
            CollectionAssert.AreEquivalent(Z3, Common.concatenate(X3, Y3));
        }

        [TestMethod]
        public void testIntArrayToString()
        {
            // null input
            try
            {
                Common.intArrayToString(null);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty input
            int[] X1 = { };
            Assert.AreEqual("", Common.intArrayToString(X1));

            // one element
            int[] X2 = { 1 };
            Assert.AreEqual("1", Common.intArrayToString(X2));

            // many elements
            int[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            Assert.AreEqual(
                    "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9",
                    Common.intArrayToString(X3));
        }

        [TestMethod]
        public void testUnsignedByteArrayToString()
        {
            // null input
            try
            {
                Common.unsignedByteArrayToString(null);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty input
            byte[] X1 = { };
            Assert.AreEqual("[]", Common.unsignedByteArrayToString(X1));

            // one element
            byte[] X2 = { 1 };
            Assert.AreEqual("[1]", Common.unsignedByteArrayToString(X2));

            // many elements
            byte[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            Assert.AreEqual(
                    "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]",
                    Common.unsignedByteArrayToString(X3));

            // range of values
            byte[] X4 = { (byte)0x00, (byte)0x7F, (byte)0x80, (byte)0xFF };
            Assert.AreEqual("[0, 127, 128, 255]", Common.unsignedByteArrayToString(X4));
        }

        [TestMethod]
        public void testByteArrayToHexString()
        {
            // null input
            try
            {
                Common.byteArrayToHexString(null);
                Assert.Fail();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // empty input
            byte[] X1 = { };
            Assert.AreEqual("", Common.byteArrayToHexString(X1));

            // one element
            byte[] X2 = { 1 };
            Assert.AreEqual("01", Common.byteArrayToHexString(X2));

            // many elements
            byte[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            Assert.AreEqual(
                    "000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809",
                    Common.byteArrayToHexString(X3));

            // range of values
            byte[] X4 = { (byte)0x00, (byte)0x7F, (byte)0x80, (byte)0xFF };
            Assert.AreEqual("007F80FF", Common.byteArrayToHexString(X4));
        }
    }
}