// SPDX-License-Identifier: MIT OR Apache-2.0
namespace IronAuth.Verify.Checks;

/// <summary>Entry point: one suite per argument, so a failure names which one (issue #118).</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: IronAuth.Verify.Checks <conformance <corpus path> | selftest | sample>");
            return 2;
        }
        return args[0] switch
        {
            "conformance" when args.Length == 2 => Conformance.Run(args[1]),
            "selftest" => SelfTest.Run(),
            "sample" => await SampleHarness.RunAsync().ConfigureAwait(false),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: IronAuth.Verify.Checks <conformance <corpus path> | selftest | sample>");
        return 2;
    }
}
