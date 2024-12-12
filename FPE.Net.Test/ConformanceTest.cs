using System;
using NUnit.Framework;

// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable EmptyGeneralCatchClause

namespace FPE.Net.Test;

/// <summary>
/// Unit test cases for conformance with the NIST sample data provided at
/// http://csrc.nist.gov/groups/ST/toolkit/examples.html.
/// 
/// To allow FF1 to output the intermediate results shown in the sample
/// data, change <see cref="Constants.CONFORMANCE_OUTPUT"/> to true.
/// 
/// Original author: Kai Johnson
/// </summary>
[TestFixture]
public class ConformanceTest
{
    [Test]
    public void testFf1Conformance()
    {
        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];

            // initialize the tweak from the sample data
            byte[] tweak = [];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [2, 4, 3, 3, 4, 7, 7, 4, 8, 4];

            testFf1Iteration("Sample #1", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
                0x32, 0x31, 0x30
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [6, 1, 2, 4, 2, 0, 0, 7, 7, 3];

            testFf1Iteration("Sample #2", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 36;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
                0x73, 0x37, 0x37, 0x37
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
            int[] ciphertext = [10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22];

            testFf1Iteration("Sample #3", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F
            ];

            // initialize the tweak from the sample data
            byte[] tweak = [];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [2, 8, 3, 0, 6, 6, 8, 1, 3, 2];

            testFf1Iteration("Sample #4", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
                0x32, 0x31, 0x30
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [2, 4, 9, 6, 6, 5, 5, 5, 4, 9];

            testFf1Iteration("Sample #5", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 36;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
                0x73, 0x37, 0x37, 0x37
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
            int[] ciphertext = [33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27];

            testFf1Iteration("Sample #6", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F,
                0x04, 0xFC, 0x6A, 0x94
            ];

            // initialize the tweak from the sample data
            byte[] tweak = [];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [6, 6, 5, 7, 6, 6, 7, 0, 0, 9];

            testFf1Iteration("Sample #7", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 10;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F,
                0x04, 0xFC, 0x6A, 0x94
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
                0x32, 0x31, 0x30
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            int[] ciphertext = [1, 0, 0, 1, 6, 2, 3, 4, 6, 3];

            testFf1Iteration("Sample #8", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 36;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F,
                0x04, 0xFC, 0x6A, 0x94
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
                0x73, 0x37, 0x37, 0x37
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
            int[] ciphertext = [33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13];

            testFf1Iteration("Sample #9", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }

        try
        {
            // initialize prerequisites from the sample data
            int radix = 256;
            int maxTlen = 256;

            // initialize the key with the sample data
            byte[] key =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5,
                0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F,
                0x04, 0xFC, 0x6A, 0x94
            ];

            // initialize the tweak from the sample data
            byte[] tweak =
            [
                0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
                0x73, 0x37, 0x37, 0x37
            ];

            // initialize plaintext and ciphertext values from the sample data
            int[] plaintext =
            [
                77, 104, 140, 63, 156, 241, 168, 217, 77, 120, 141, 248, 199, 103, 250, 164, 56, 175,
                134, 207, 120, 221, 126, 109, 156, 169, 100, 89, 115, 18, 217, 150, 78, 71, 81, 206, 168, 98, 98,
                156, 95, 122, 38, 63, 68, 30, 212, 125, 250, 155, 29, 218, 189, 20, 234, 97, 130, 113, 229, 168,
                221, 55, 161, 90, 45, 240, 130, 241, 58, 61, 170, 204, 41, 160, 144, 147, 174, 65, 87, 23
            ];
            int[] ciphertext =
            [
                68, 111, 39, 159, 6, 189, 255, 68, 203, 183, 154, 249, 35, 48, 199, 152, 118, 215, 63,
                117, 164, 44, 164, 195, 236, 192, 41, 33, 25, 92, 8, 156, 151, 239, 253, 22, 223, 23, 228, 167, 170,
                8, 34, 25, 11, 181, 38, 5, 111, 145, 154, 135, 59, 238, 62, 185, 132, 63, 216, 218, 107, 179, 121,
                95, 87, 20, 239, 2, 80, 133, 216, 171, 142, 192, 139, 64, 105, 203, 160, 125
            ];

            testFf1Iteration("Test Concatenation in Step 6. iii.", radix, maxTlen, key, tweak, plaintext, ciphertext);
        }
        catch (Exception)
        {
            Assert.Fail();
        }
    }

    ///<summary>
    ///Perform a single test of FF1 encryption and decryption.
    ///</summary>
    ///<param name="plaintext">The plaintext input.</param>
    ///<param name="ciphertext">The expected ciphertext output.</param>
    ///<param name="key">The AES key.</param>
    ///<param name="name">The name of the test.</param>
    ///<param name="radix">The radix used in plaintext and ciphertext arguments.</param>
    ///<param name="tweak">The tweak.</param>
    ///<param name="maxTlen">The maximum length of a tweak.</param>
    private void testFf1Iteration(String name, int radix, int maxTlen, byte[] key, byte[] tweak, int[] plaintext,
        int[] ciphertext)
    {
        // create an FF1 instance
        FF1 ff1 = new FF1(radix, maxTlen);
        Assert.That(ff1, Is.Not.Null);

        // create an AES key from the key data
        byte[] K = key;


        Console.WriteLine("\n==============================================================\n");
        Console.WriteLine(name + "\n");
        Console.WriteLine("FF1-AES" + key.Length * 8 + "\n");
        Console.WriteLine("Key is " + Common.byteArrayToHexString(key));
        Console.WriteLine("Radix = " + radix);
        Console.WriteLine("--------------------------------------------------------------\n");
        Console.WriteLine("PT is <" + Common.intArrayToString(plaintext) + ">\n");

        // perform the encryption
        int[] ct = ff1.encrypt(K, tweak, plaintext);

        Console.WriteLine("CT is <" + Common.intArrayToString(ct) + ">");

        // validate the ciphertext
        Assert.That(ciphertext, Is.EquivalentTo(ct));

        Console.WriteLine("\n--------------------------------------------------------------\n");

        // perform the decryption
        int[] pt = ff1.decrypt(K, tweak, ct);

        Console.WriteLine("PT is <" + Common.intArrayToString(pt) + ">");

        // validate the recovered plaintext
        Assert.That(plaintext, Is.EquivalentTo(pt));
    }
}
