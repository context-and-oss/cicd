using DotnetMtpApp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotnetMtpApp.Tests;

[TestClass]
public class CalculatorTests
{
    [TestMethod]
    public void AddsTwoNumbers()
    {
        Assert.AreEqual(5, Calculator.Add(2, 3));
    }

    [TestMethod]
    public void MultipliesTwoNumbers()
    {
        Assert.AreEqual(6, Calculator.Multiply(2, 3));
    }
}
