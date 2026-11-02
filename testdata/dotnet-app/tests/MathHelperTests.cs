using Xunit;
using DotnetApp;

namespace DotnetApp.Tests;

public class MathHelperTests
{
    [Fact]
    public void Divide_ReturnsCorrectResult()
    {
        Assert.Equal(5, MathHelper.Divide(10, 2));
    }
}
