using System;
using NUnit.Framework;

// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable EmptyGeneralCatchClause

namespace FPE.Net.Test;

/**
 * JUnit test cases for the Constants class
 *
 * @author Kai Johnson
 *
 */
[TestFixture]
public class ConstantsTest {

    [Test]
    public void testConstants() {
            // validate values of MINLEN and MAXLEN
            Assert.That(Constants.MINLEN >= 2);
            Assert.That(Constants.MINLEN <= Constants.MAXLEN);
            Assert.That(Constants.MAXLEN <= Math.Pow(2, 32));

            // validate values of MINRADIX and MAXRADIX
            Assert.That(Constants.MINRADIX >= 2);
            Assert.That(Constants.MINRADIX <= Constants.MAXRADIX);
            Assert.That(Constants.MAXRADIX <= Math.Pow(2, 16));

        }

}
