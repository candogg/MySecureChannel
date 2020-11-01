public class SessionKeyRequestModel
{
    public string SessionId { get; set; }
    public string ClientPublic { get; set; }

    public bool IsValid()
    {
        if (!string.IsNullOrEmpty(SessionId) && !string.IsNullOrWhiteSpace(SessionId) && !string.IsNullOrEmpty(ClientPublic) && !string.IsNullOrWhiteSpace(ClientPublic))
        {
            return true;
        }

        return false;
    }
}