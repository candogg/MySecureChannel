using Microsoft.Win32.SafeHandles;
using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Runtime.InteropServices;

public class SqlProvider : IDisposable
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

    public string GetClientId(string clientSecret)
    {
        try
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.ConnectionStrings["ConStr"].ConnectionString))
            using (SqlCommand cmd = new SqlCommand("SELECT C.CLIENT_ID FROM CAUTH_CLIENTS AS C WHERE C.ACTIVE = 1 AND C.CLIENT_SECRET = @SECRET", con))
            {
                cmd.Parameters.Clear();

                SqlParameter param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.VarChar,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@SECRET",
                    IsNullable = false,
                    Size = 500,
                    Value = clientSecret
                };

                cmd.Parameters.Add(param);

                if (con.State == System.Data.ConnectionState.Closed)
                {
                    con.Open();
                }

                using (SqlDataReader reader = cmd.ExecuteReader(System.Data.CommandBehavior.CloseConnection))
                {
                    if (reader.Read())
                    {
                        return reader.GetGuid(0).ToString();
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            //writelog
        }

        return null;
    }

    public KeyModel GetSessionKeys(Guid sessionId)
    {
        try
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.ConnectionStrings["ConStr"].ConnectionString))
            using (SqlCommand cmd = new SqlCommand("SELECT TOP 1 S.CLIENT_ID, S.PRIVATE_KEY, S.SESSION_KEY, S.SESSION_IVKEY FROM CAUTH_SESSIONS AS S WHERE S.ACTIVE = 1 AND GETDATE() BETWEEN S.START_TIME AND S.END_TIME AND S.SESSION_ID = @SESSION_ID ORDER BY S.START_TIME DESC", con))
            {
                cmd.Parameters.Clear();

                SqlParameter param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.UniqueIdentifier,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@SESSION_ID",
                    IsNullable = false,
                    Value = sessionId
                };
                cmd.Parameters.Add(param);

                if (con.State == System.Data.ConnectionState.Closed)
                {
                    con.Open();
                }

                using (SqlDataReader reader = cmd.ExecuteReader(System.Data.CommandBehavior.CloseConnection))
                {
                    if (reader.Read())
                    {
                        return new KeyModel()
                        {
                            SessionId = sessionId,
                            ClientId = reader.GetGuid(0),
                            PrivateKey = reader.GetString(1),
                            EncKey = reader.GetString(2),
                            IVKey = reader.GetString(3)
                        };
                    }
                }
            }
        }
        catch (Exception ex)
        {
            //writelog
        }

        return null;
    }

    public string CreateClientSession(Guid clientId, string privateKey, string encKey, string ivKey)
    {
        try
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.ConnectionStrings["ConStr"].ConnectionString))
            using (SqlCommand cmd = new SqlCommand("UPDATE CAUTH_SESSIONS SET ACTIVE = 0 WHERE CLIENT_ID = @CLIENT_ID; INSERT INTO CAUTH_SESSIONS (CLIENT_ID, PRIVATE_KEY,  SESSION_KEY, SESSION_IVKEY) VALUES (@CLIENT_ID, @PRIVATE_KEY, @SESSION_KEY, @SESSION_IVKEY); SELECT TOP 1 S.SESSION_ID FROM CAUTH_SESSIONS AS S INNER JOIN CAUTH_CLIENTS AS C ON C.CLIENT_ID = S.CLIENT_ID WHERE C.ACTIVE = 1 AND C.CLIENT_ID = @CLIENT_ID AND GETDATE() BETWEEN S.START_TIME AND S.END_TIME AND S.ACTIVE = 1 ORDER BY S.START_TIME DESC", con))
            {
                cmd.Parameters.Clear();

                SqlParameter param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.UniqueIdentifier,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@CLIENT_ID",
                    IsNullable = false,
                    Value = clientId
                };
                cmd.Parameters.Add(param);

                param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.VarChar,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@PRIVATE_KEY",
                    IsNullable = false,
                    Size = 2000,
                    Value = privateKey
                };
                cmd.Parameters.Add(param);

                param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.VarChar,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@SESSION_KEY",
                    IsNullable = false,
                    Size = 50,
                    Value = encKey
                };
                cmd.Parameters.Add(param);

                param = new SqlParameter()
                {
                    SqlDbType = System.Data.SqlDbType.VarChar,
                    Direction = System.Data.ParameterDirection.Input,
                    ParameterName = "@SESSION_IVKEY",
                    IsNullable = false,
                    Size = 50,
                    Value = ivKey
                };
                cmd.Parameters.Add(param);

                if (con.State == System.Data.ConnectionState.Closed)
                {
                    con.Open();
                }

                using (SqlDataReader reader = cmd.ExecuteReader(System.Data.CommandBehavior.CloseConnection))
                {
                    if (reader.Read())
                    {
                        return reader.GetGuid(0).ToString();
                    }
                    else
                    {
                        return "NO_SESSION";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            //writelog
        }

        return null;
    }
}