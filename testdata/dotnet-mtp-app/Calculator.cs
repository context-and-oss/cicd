namespace DotnetMtpApp;

// Deliberately more code than the tests reach: an instrumented assembly with
// partial coverage is what proves the harvested cobertura carries a real figure.
// A 100% fixture cannot tell a measurement apart from the empty report an
// uninstrumented project writes, which is exactly the state this fixture exists
// to distinguish.
public static class Calculator
{
    public static int Add(int a, int b) => a + b;

    public static int Multiply(int a, int b) => a * b;

    public static int Subtract(int a, int b) => a - b;

    public static int Divide(int a, int b)
    {
        if (b == 0)
        {
            throw new DivideByZeroException();
        }

        return a / b;
    }
}
