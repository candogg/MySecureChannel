public class KeyRequestModel
{
    public string ClientSecret { get; set; }

    public bool IsValid()
    {
        if(!string.IsNullOrEmpty(ClientSecret) && !string.IsNullOrWhiteSpace(ClientSecret))
        {
            return true;
        }

        return false;
    }
}