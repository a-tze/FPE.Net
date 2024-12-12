/*
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
using System.Numerics;
using NUnit.Framework;
// ReSharper disable CompareOfFloatsByEqualityOperator

// ReSharper disable EmptyGeneralCatchClause
// ReSharper disable ExpressionIsAlwaysNull

namespace FPE.Net.Test;

/**
 * Unit test cases for the Common class.
 *
 * @author Kai Johnson
 *
 */
[TestFixture]
public class CommonTest
{
    [Test]
    public void testTestNumIntArrayInt()
    {
        // example from NIST SP 800-38G
        int[] X1 = [0, 0, 0, 1, 1, 0, 1, 0];
        Assert.That(Common.num(X1, 5).CompareTo(755) == 0);

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
            int[] X = [];
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
            int[] X = [0, 1, 2, 3, 4, 5];
            Common.num(X, 1);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // radix too large
        try
        {
            int[] X = [0, 1, 2, 3, 4, 5];
            Common.num(X, 65537);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // values outside the range of the radix
        try
        {
            int[] X = [0, 1, 2, 3, 4, 5];
            Common.num(X, 4);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // negative values
        try
        {
            int[] X = [0, 1, -2, 3, 4, 5];
            Common.num(X, 4);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // byte value
        int[] X2 = [1, 1, 1, 1, 1, 1, 1, 1];
        Assert.That(Common.num(X2, 2).CompareTo(255) == 0);

        // short value
        int[] X3 = [15, 15, 15, 15];
        Assert.That(Common.num(X3, 16).CompareTo(65535) == 0);

        // int value
        int[] X4 = [127, 255, 255, 255];
        Assert.That(Common.num(X4, 256).CompareTo(Int32.MaxValue) == 0);

        // long value
        int[] X5 = [255, 255, 255, 255];
        Assert.That(Common.num(X5, 256).CompareTo(4294967295L) == 0);

        // yotta
        int[] X6 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.That(Common.num(X6, 256) == new BigInteger(Math.Pow(2, 80)));
    }

    [Test]
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
            byte[] X = [];
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
        byte[] X1 = [0x00];
        Assert.That(0 == Common.num(X1));
        byte[] X2 = [0x01];
        Assert.That(1 == Common.num(X2));
        byte[] X3 = [0x80];
        Assert.That(128 == Common.num(X3));
        byte[] X4 = [0xFF];
        Assert.That(255 == Common.num(X4));

        // two byte values
        byte[] X5 = [0x00, 0x00];
        Assert.That(0 == Common.num(X5));
        byte[] X6 = [0x00, 0x01];
        Assert.That(1 == Common.num(X6));
        byte[] X7 = [0x80, 0x00];
        Assert.That(32768 == Common.num(X7));
        byte[] X8 = [0xFF, 0xFF];
        Assert.That(65535 == Common.num(X8));

        // four byte values
        byte[] X9 = [0x00, 0x00, 0x00, 0x00];
        Assert.That(0 == Common.num(X9));
        byte[] X10 = [0x00, 0x00, 0x00, 0x01];
        Assert.That(1 == Common.num(X10));
        byte[] X11 = [0x80, 0x00, 0x00, 0x00];
        Assert.That(2147483648L == Common.num(X11));
        byte[] X12 = [0xFF, 0xFF, 0xFF, 0xFF];
        Assert.That(4294967295L == Common.num(X12));

        // yotta
        byte[] X13 =
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];
        Assert.That(new BigInteger(Math.Pow(2, 80)) == Common.num(X13));
    }

    [Test]
    public void testStr()
    {
        // example from NIST SP 800-38G
        int[] expected1 = [0, 3, 10, 7];
        Assert.That(expected1, Is.EquivalentTo(Common.str(559, 12, 4)));

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
        int[] X2 = [1, 1, 1, 1, 1, 1, 1, 1];
        Assert.That(X2, Is.EquivalentTo(Common.str(255, 2, 8)));

        // short value
        int[] X3 = [15, 15, 15, 15];
        Assert.That(X3, Is.EquivalentTo(Common.str(65535, 16, 4)));

        // int value
        int[] X4 = [127, 255, 255, 255];
        Assert.That(X4, Is.EquivalentTo(Common.str(Int32.MaxValue, 256, 4)));

        // long value
        int[] X5 = [255, 255, 255, 255];
        Assert.That(X5, Is.EquivalentTo(Common.str(4294967295L, 256, 4)));

        // yotta
        int[] X6 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.That(X6, Is.EquivalentTo(Common.str(new BigInteger(Math.Pow(2, 80)), 256, 11)));
    }

    [Test]
    public void testRev()
    {
        // example from NIST SP 800-38G
        int[] X1 = [1, 3, 5, 7, 9];
        int[] Y1 = [9, 7, 5, 3, 1];
        Assert.That(Y1, Is.EquivalentTo(Common.rev(X1)));

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
        int[] X2 = [];
        int[] Y2 = [];
        Assert.That(Y2,Is.EquivalentTo( Common.rev(X2)));

        // one element
        int[] X3 = [5];
        int[] Y3 = [5];
        Assert.That(Y3, Is.EquivalentTo(Common.rev(X3)));

        // many elements
        int[] X4 =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        ];
        int[] Y4 =
        [
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
            6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
        ];
        Assert.That(Y4, Is.EquivalentTo(Common.rev(X4)));
    }

    [Test]
    public void testRevb()
    {
        // example from NIST SP 800-38G
        byte[] X1 = [1, 2, 3];
        byte[] Y1 = [3, 2, 1];
        Assert.That(Y1, Is.EquivalentTo(Common.revb(X1)));

        // null input
        try
        {
            Common.revb(null);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty array
        byte[] X2 = [];
        byte[] Y2 = [];
        Assert.That(Y2, Is.EquivalentTo(Common.revb(X2)));

        // one element
        byte[] X3 = [5];
        byte[] Y3 = [5];
        Assert.That(Y3, Is.EquivalentTo(Common.revb(X3)));

        // many elements
        byte[] X4 =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        ];
        byte[] Y4 =
        [
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
            6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
        ];
        Assert.That(Y4, Is.EquivalentTo(Common.revb(X4)));
    }

    [Test]
    public void testXor()
    {
        // example from NIST SP 800-38G
        byte[] X1 = [0x13];
        byte[] Y1 = [0x15];
        byte[] Z1 = [0x06];
        Assert.That(Z1, Is.EquivalentTo(Common.xor(X1, Y1)));

        // null input
        try
        {
            byte[] X = null;
            byte[] Y = [0xA5];
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            byte[] X = [0x0F];
            byte[] Y = null;
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // mismatched length
        try
        {
            byte[] X = [0x0F, 0xF0];
            byte[] Y = [0xA5];
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // empty arrays
        try
        {
            byte[] X = [];
            byte[] Y = [0xA5];
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        try
        {
            byte[] X = [0x0F];
            byte[] Y = [];
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
            byte[] Y = [0xA5];
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        try
        {
            byte[] X = [0x0F];
            byte[] Y = new byte[Constants.MAXLEN + 1];
            Common.xor(X, Y);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // one element
        byte[] X2 = [0x0F];
        byte[] Y2 = [0xA5];
        byte[] Z2 = [0xAA];
        Assert.That(Z2,Is.EquivalentTo( Common.xor(X2, Y2)));

        // many elements
        byte[] X3 = [0x0F, 0xF0, 0xFF, 0x00];
        byte[] Y3 = [0xA5, 0xA5, 0xA5, 0xA5];
        byte[] Z3 = [0xAA, 0x55, 0x5A, 0xA5];
        Assert.That(Z3, Is.EquivalentTo(Common.xor(X3, Y3)));
    }

    [Test]
    public void testLog2()
    {
        // examples from NIST SP 800-38G
        Assert.That(Common.log2(64) == 6);
        Assert.That(Common.log2(10) == Math.Log(10) / Math.Log(2));

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
        Assert.That(Common.log2(1024) == 10.0d);

        // real result
        Assert.That(Common.log2(1023) < 10);
        Assert.That(Common.log2(1025) > 10);
    }

    [Test]
    public void testFloor()
    {
        // examples from NIST SP 800-38G
        Assert.That(2 == Common.floor(2.1));
        Assert.That(4 == Common.floor((double)4));

        // correct usage
        Assert.That(2 == Common.floor(7 / (double)3));
        Assert.That(2 == Common.floor(7 / 3.0));

        // incorrect usage
        try
        {
            Assert.That(2 == Common.floor(7 / 3));
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // native integer division
        Assert.That(2 == 7 / 3);
    }

    [Test]
    public void testCeiling()
    {
        // examples from NIST SP 800-38G
        Assert.That(3 == Common.ceiling(2.1));
        Assert.That(4 == Common.ceiling((double)4));

        // correct usage
        Assert.That(3 == Common.ceiling(7 / (double)3));
        Assert.That(3 == Common.ceiling(7 / 3.0));

        // incorrect usage
        try
        {
            Assert.That(3 == Common.ceiling(7 / 3));
            Assert.Fail();
        }
        catch (Exception)
        {
        }
    }

    [Test]
    public void testModIntInt()
    {
        // examples from NIST SP 800-38G
        Assert.That(4 == Common.mod(-3, 7));
        Assert.That(6 == Common.mod(13, 7));

        // negative modulus
        /*

   Note that Math.floorMod() permits negative moduli where NIST SP

   800-38G does not.

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

    [Test]
    public void testModBigIntegerBigInteger()
    {
        // examples from NIST SP 800-38G
        Assert.That(Common.mod(-3, 7) == 4);
        Assert.That(Common.mod(13, 7) == 6);

        // equivalence to BigInteger.mod()

        // NOTE: in .NET, BigInteger behaves differently,
        // therefore the negative test is useless
        //Assert.That(new BigInteger(-3) % 7, 4);
        Assert.That(new BigInteger(13) % 7 == 6);

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
            _ = new BigInteger(13) % -7;
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
            _ = new BigInteger(13) % BigInteger.Zero;
            Assert.Fail();
        }
        catch (Exception)
        {
        }
    }

    [Test]
    public void testBytestringIntInt()
    {
        // example from NIST SP 800-38G
        byte[] expected1 = [0x01];
        Assert.That(expected1, Is.EquivalentTo(Common.bytestring(1, 1)));

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
        byte[] expected2 = [0xFF];
        Assert.That(expected2, Is.EquivalentTo(Common.bytestring(255, 1)));

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
        byte[] expected4 = [0x00, 0x01];
        Assert.That(expected4, Is.EquivalentTo(Common.bytestring(1, 2)));

        byte[] expected5 = [0xFF, 0xFF];
        Assert.That(expected5, Is.EquivalentTo(Common.bytestring(65535, 2)));

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
        byte[] expected7 =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01
        ];
        Assert.That(expected7, Is.EquivalentTo(Common.bytestring(1, 16)));

        byte[] expected8 =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF,
            0xFF
        ];
        Assert.That(expected8, Is.EquivalentTo(Common.bytestring(Int32.MaxValue, 16)));
    }

    [Test]
    public void testBytestringBigIntegerInt()
    {
        // example from NIST SP 800-38G
        byte[] expected1 = [0x01];
        Assert.That(expected1, Is.EquivalentTo(Common.bytestring(BigInteger.One, 1)));

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
        byte[] expected2 = [0xFF];
        Assert.That(expected2, Is.EquivalentTo(Common.bytestring(255, 1)));

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
        byte[] expected4 = [0x00, 0x01];
        Assert.That(expected4, Is.EquivalentTo(Common.bytestring(BigInteger.One, 2)));

        byte[] expected5 = [0xFF, 0xFF];
        Assert.That(expected5, Is.EquivalentTo(Common.bytestring(65535, 2)));

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
        byte[] expected7 =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01
        ];
        Assert.That(expected7, Is.EquivalentTo(Common.bytestring(BigInteger.One, 16)));

        byte[] expected8 =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF,
            0xFF
        ];
        Assert.That(expected8, Is.EquivalentTo(Common.bytestring(Int32.MaxValue, 16)));
    }

    [Test]
    public void testBitstring()
    {
        // example from NIST SP 800-38G
        byte[] expected1 = [0];
        Assert.That(expected1, Is.EquivalentTo(Common.bitstring(false, 8)));

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
        byte[] expected2 = [0, 0];
        Assert.That(expected2, Is.EquivalentTo(Common.bitstring(false, 16)));
        byte[] expected3 = [0xFF, 0xFF];
        Assert.That(expected3, Is.EquivalentTo(Common.bitstring(true, 16)));

        // 16 byte values
        byte[] expected4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.That(expected4, Is.EquivalentTo(Common.bitstring(false, 128)));
        byte[] expected5 =
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF
        ];
        Assert.That(expected5, Is.EquivalentTo(Common.bitstring(true, 128)));
    }

    [Test]
    public void testConcatenateIntArrayIntArray()
    {
        // example from NIST SP 800-38G
        int[] X1 = [3, 1];
        int[] Y1 = [31, 8, 10];
        int[] Z1 = [3, 1, 31, 8, 10];
        Assert.That(Z1, Is.EquivalentTo(Common.concatenate(X1, Y1)));

        // null input
        try
        {
            int[] X = [1, 2, 3];
            Common.concatenate(X, null);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            int[] Y = [4, 5, 6];
            Common.concatenate(null, Y);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty input
        int[] X2 = [1, 2, 3];
        int[] Y2 = [];
        int[] Z2 = [1, 2, 3];
        Assert.That(Z2, Is.EquivalentTo(Common.concatenate(X2, Y2)));
        int[] X3 = [];
        int[] Y3 = [4, 5, 6];
        int[] Z3 = [4, 5, 6];
        Assert.That(Z3, Is.EquivalentTo(Common.concatenate(X3, Y3)));
    }

    [Test]
    public void testConcatenateByteArrayByteArray()
    {
        // example from NIST SP 800-38G
        byte[] X1 = [3, 1];
        byte[] Y1 = [31, 8, 10];
        byte[] Z1 = [3, 1, 31, 8, 10];
        Assert.That(Z1, Is.EquivalentTo(Common.concatenate(X1, Y1)));

        // null input
        try
        {
            byte[] X = [1, 2, 3];
            Common.concatenate(X, null);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            byte[] Y = [4, 5, 6];
            Common.concatenate(null, Y);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty input
        byte[] X2 = [1, 2, 3];
        byte[] Y2 = [];
        byte[] Z2 = [1, 2, 3];
        Assert.That(Z2, Is.EquivalentTo(Common.concatenate(X2, Y2)));
        byte[] X3 = [];
        byte[] Y3 = [4, 5, 6];
        byte[] Z3 = [4, 5, 6];
        Assert.That(Z3, Is.EquivalentTo(Common.concatenate(X3, Y3)));
    }

    [Test]
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
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty input
        int[] X1 = [];
        Assert.That("" == Common.intArrayToString(X1));

        // one element
        int[] X2 = [1];
        Assert.That("1" == Common.intArrayToString(X2));

        // many elements
        int[] X3 =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        ];
        Assert.That(
            "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9" ==
            Common.intArrayToString(X3));
    }

    [Test]
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
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty input
        byte[] X1 = [];
        Assert.That("[]" == Common.unsignedByteArrayToString(X1));

        // one element
        byte[] X2 = [1];
        Assert.That("[1]" == Common.unsignedByteArrayToString(X2));

        // many elements
        byte[] X3 =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        ];
        Assert.That(
            "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]" ==
            Common.unsignedByteArrayToString(X3));

        // range of values
        byte[] X4 = [0x00, 0x7F, 0x80, 0xFF];
        Assert.That("[0, 127, 128, 255]" == Common.unsignedByteArrayToString(X4));
    }

    [Test]
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
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // empty input
        byte[] X1 = [];
        Assert.That("" == Common.byteArrayToHexString(X1));

        // one element
        byte[] X2 = [1];
        Assert.That("01" == Common.byteArrayToHexString(X2));

        // many elements
        byte[] X3 =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        ];
        Assert.That(
            "000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809" ==
            Common.byteArrayToHexString(X3));

        // range of values
        byte[] X4 = [0x00, 0x7F, 0x80, 0xFF];
        Assert.That("007F80FF" == Common.byteArrayToHexString(X4));
    }
}
