using Microsoft.Win32.SafeHandles;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class RSAOperations : IDisposable
{
    private bool _disposed = false;
    private readonly SafeHandle _safeHandle = new SafeFileHandle(IntPtr.Zero, true);

    public void Dispose() => Dispose(true);

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            // Dispose managed state (managed objects).
            _safeHandle?.Dispose();
        }

        _disposed = true;
    }

    public Tuple<string, string> GetNewKeyPair()
    {
        try
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            string privateKey;
            string publicKey;
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));

            AsymmetricCipherKeyPair asymmetricCipherKeyPair = rsaKeyPairGenerator.GenerateKeyPair();
            AsymmetricKeyParameter @private = asymmetricCipherKeyPair.Private;
            AsymmetricKeyParameter @public = asymmetricCipherKeyPair.Public;

            using (TextWriter privateWriter = new StringWriter())
            {
                PemWriter privatePemWriter = new PemWriter(privateWriter);
                privatePemWriter.WriteObject(@private);
                privatePemWriter.Writer.Flush();
                privateKey = privateWriter.ToString();
            }

            using (TextWriter publicWriter = new StringWriter())
            {
                PemWriter publicPemWriter = new PemWriter(publicWriter);
                publicPemWriter.WriteObject(@public);
                publicPemWriter.Writer.Flush();
                publicKey = publicWriter.ToString();
            }

            return new Tuple<string, string>(publicKey, privateKey);
        }
        catch
        { }

        return new Tuple<string, string>(string.Empty, string.Empty);
    }

    public string Encrypt(string publicKey, string plainText)
    {
        try
        {
            RsaEngine rsaEngine = new RsaEngine();

            using (TextReader reader = new StringReader(publicKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricKeyParameter parameters = (AsymmetricKeyParameter)pemReader.ReadObject();

                rsaEngine.Init(true, parameters);

                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(rsaEngine.ProcessBlock(bytes, 0, bytes.Length));
            }
        }
        catch
        { }

        return string.Empty;
    }

    public string Decrypt(string privateKey, string cipherText)
    {
        try
        {
            RsaEngine rsaEngine = new RsaEngine();

            using (TextReader reader = new StringReader(privateKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                rsaEngine.Init(false, asymmetricCipherKeyPair.Private);

                byte[] bytes = Convert.FromBase64String(cipherText);

                return Encoding.UTF8.GetString(rsaEngine.ProcessBlock(bytes, 0, bytes.Length));
            }
        }
        catch
        { }

        return string.Empty;
    }

    public string GetSecureRandomString(int length)
    {
        const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_=/()?*&%+!}[]{-";
        StringBuilder res = new StringBuilder();
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            byte[] uintBuffer = new byte[sizeof(uint)];

            while (length-- > 0)
            {
                rng.GetBytes(uintBuffer);
                uint num = BitConverter.ToUInt32(uintBuffer, 0);
                res.Append(valid[(int)(num % (uint)valid.Length)]);
            }
        }

        return res.ToString();
    }
}