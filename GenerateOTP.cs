using System.Text;
using System.Security.Cryptography;
using OtpNet;

public class GenerateOTP //using manual
{
    public static string GenerateTOTP(int digits = 6, int timeStep = 30)
    {
        string secret = "SECRETKEY"; //insert secret from qr code
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

    public static string GenerateMyOTP() // using library
    {
        string secretKey = "SECRETKEY"; //insert secret from qr code
        string uppercaseKey = secretKey.ToUpper();
        byte[] secretKeyBytes = Base32Encoding.ToBytes(uppercaseKey);
        var totp = new Totp(secretKeyBytes);
        string generatedOtp = totp.ComputeTotp();

        return generatedOtp;
    }
}