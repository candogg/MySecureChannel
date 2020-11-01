using System;
using System.Text;
using System.Web.Http;

namespace CAuthService.Controllers
{
    public class AuthController : ApiController
    {
        [HttpPost]
        public ResponseModel CreateSession([FromBody] KeyRequestModel _clientInfo)
        {
            if (_clientInfo.IsValid())
            {
                using (SqlProvider sqlOp = new SqlProvider())
                using (RSAOperations keyOp = new RSAOperations())
                {
                    string clientId = sqlOp.GetClientId(_clientInfo.ClientSecret);

                    if (!string.IsNullOrEmpty(clientId))
                    {
                        Tuple<string, string> asymmetricKeyPair = keyOp.GetNewKeyPair();

                        if (!string.IsNullOrEmpty(asymmetricKeyPair.Item1) && !string.IsNullOrEmpty(asymmetricKeyPair.Item2))
                        {
                            string sessionEncKey = keyOp.GetSecureRandomString(16);
                            string sessionIvKey = keyOp.GetSecureRandomString(16);

                            while (sessionEncKey.Equals(sessionIvKey))
                            {
                                sessionIvKey = keyOp.GetSecureRandomString(16);
                            }

                            string newSessionId = sqlOp.CreateClientSession(new Guid(clientId), asymmetricKeyPair.Item2, sessionEncKey, sessionIvKey);

                            if (!string.IsNullOrEmpty(newSessionId))
                            {
                                return new ResponseModel() { SessionId = newSessionId, PublicKey = asymmetricKeyPair.Item1 };
                            }
                        }
                    }
                }
            }

            return null;
        }

        [HttpPost]
        public ResponseModel ShareSessionKeys([FromBody] SessionKeyRequestModel _clientInfo)
        {
            if (_clientInfo.IsValid())
            {
                using (SqlProvider sqlOp = new SqlProvider())
                using (RSAOperations keyOp = new RSAOperations())
                {
                    KeyModel sessionParameters = sqlOp.GetSessionKeys(new Guid(_clientInfo.SessionId));

                    if (sessionParameters != null && !string.IsNullOrEmpty(sessionParameters.PrivateKey) && !string.IsNullOrEmpty(sessionParameters.EncKey) && !string.IsNullOrEmpty(sessionParameters.IVKey))
                    {
                        string clientPublicKey = string.Empty;

                        foreach (string chunk in _clientInfo.ClientPublic.Split('≡'))
                        {
                            clientPublicKey += keyOp.Decrypt(sessionParameters.PrivateKey, chunk);
                        }

                        if (!string.IsNullOrEmpty(clientPublicKey))
                        {
                            string encryptedEKey = keyOp.Encrypt(clientPublicKey, sessionParameters.EncKey);
                            string encryptedIKey = keyOp.Encrypt(clientPublicKey, sessionParameters.IVKey);

                            return new ResponseModel() { EKey = encryptedEKey, IKey = encryptedIKey };
                        }
                    }
                }
            }

            return null;
        }

        [HttpPost]
        public MessageModel GetServerMessage([FromBody] MessageModel _clientMessage)
        {
            if(_clientMessage.IsValid())
            {
                try
                {
                    using (SqlProvider sqlOp = new SqlProvider())
                    using (AESOperations aesOp = new AESOperations())
                    {
                        KeyModel sessionParameters = sqlOp.GetSessionKeys(new Guid(_clientMessage.SessionId));

                        if (sessionParameters != null && !string.IsNullOrEmpty(sessionParameters.PrivateKey) && !string.IsNullOrEmpty(sessionParameters.EncKey) && !string.IsNullOrEmpty(sessionParameters.IVKey))
                        {
                            string clientMessage = aesOp.Decrypt(_clientMessage.Message, Encoding.ASCII.GetBytes(sessionParameters.EncKey), Encoding.ASCII.GetBytes(sessionParameters.IVKey));

                            if(clientMessage.Equals("MESSAGE FROM CLIENT"))
                            {
                                return new MessageModel() { Message = aesOp.Encrypt("LEGIT CLIENT", Encoding.ASCII.GetBytes(sessionParameters.EncKey), Encoding.ASCII.GetBytes(sessionParameters.IVKey)) };
                            }
                        }
                    }
                }
                catch
                { }
            }

            return null;
        }
    }
}
