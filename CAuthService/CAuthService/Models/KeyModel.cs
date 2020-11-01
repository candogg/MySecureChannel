using System;

public class KeyModel
{
    public Guid SessionId { get; set; }
    public Guid ClientId { get; set; }
    public string PrivateKey { get; set; }
    public string PublicKey { get; set; }
    public string EncKey { get; set; }
    public string IVKey { get; set; }

    public bool IsValid()
    {
        if(!string.IsNullOrEmpty(PrivateKey) && !string.IsNullOrEmpty(PublicKey))
        {
            return true;
        }

        return false;
    }
}