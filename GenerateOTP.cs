using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
//using System.Threading.Tasks;
//using OtpSharp;
//using Base32;

public class GenerateOTP
{
    public static string GenerateTOTP(int digits = 6, int timeStep = 30)
    {
        string secret = "SECRETKEY"; // ntar dibikin secret beneran
        string uppercaseKey = secret.ToUpper();
        long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeStep;
        return GenerateHOTP(uppercaseKey, counter, digits);
    }

    private static string GenerateHOTP(string secret, long counter, int digits)
    {
        byte[] key = Encoding.UTF8.GetBytes(secret);
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

        using (var hmac = new HMACSHA256(key))
        {
            byte[] hash = hmac.ComputeHash(counterBytes);
            int offset = hash[^1] & 0xF;
            int binaryCode = (hash[offset] & 0x7F) << 24 |
                             (hash[offset + 1] & 0xFF) << 16 |
                             (hash[offset + 2] & 0xFF) << 8 |
                             (hash[offset + 3] & 0xFF);

            int otp = binaryCode % (int)Math.Pow(10, digits);
            return otp.ToString(new string('0', digits));
        }
    }
}