public class MessageModel
{
    public string SessionId { get; set; }
    public string Message { get; set; }

    public bool IsValid()
    {
        if (!string.IsNullOrEmpty(SessionId) && !string.IsNullOrWhiteSpace(Message))
        {
            return true;
        }

        return false;
    }
}