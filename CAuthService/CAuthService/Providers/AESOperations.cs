using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class AESOperations : IDisposable
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

    public string Encrypt(string plainText, byte[] Key, byte[] IV)
    {
        byte[] encrypted = null;

        try
        {
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        encrypted = ms.ToArray();
                    }
                }
            }
        }
        catch
        { }

        return Convert.ToBase64String(encrypted);
    }

    public string Decrypt(string cipherText, byte[] Key, byte[] IV)
    {
        string plaintext = null;

        try
        {
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cs))
                        {
                            plaintext = reader.ReadToEnd();
                        }
                    }
                }
            }
        }
        catch(Exception ex)
        { }

        return plaintext;
    }
}