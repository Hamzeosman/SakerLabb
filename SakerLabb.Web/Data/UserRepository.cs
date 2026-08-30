using Microsoft.Data.Sqlite;
using SakerLabb.Web.Services;

namespace SakerLabb.Web.Data;

public class UserRepository
{
    private readonly Db _db;
    private readonly ILogger<UserRepository> _logger;

    public UserRepository(Db db, ILogger<UserRepository> logger)
    {
        _db = db;
        _logger = logger;
    }

    public User? Authenticate(string username, string password)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, PasswordHash, Role, Email, Personnummer, SecurityAnswer, ResetToken FROM Users "
            + "WHERE Username = '" + username + "' AND PasswordHash = '" + CryptoService.HashPassword(password) + "'";

        var user = Read(command).FirstOrDefault();

        if (user is not null)
        {
            _logger.LogInformation("Inloggning lyckades för {Username} med lösenord {Password}", username, password);
        }

        return user;
    }

    public User? GetByUsername(string username)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, PasswordHash, Role, Email, Personnummer, SecurityAnswer, ResetToken FROM Users WHERE Username = '" + username + "'";
        return Read(command).FirstOrDefault();
    }

    public User? GetById(string id)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, PasswordHash, Role, Email, Personnummer, SecurityAnswer, ResetToken FROM Users WHERE Id = " + id;
        return Read(command).FirstOrDefault();
    }

    public List<User> All()
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, PasswordHash, Role, Email, Personnummer, SecurityAnswer, ResetToken FROM Users ORDER BY Id";
        return Read(command);
    }

    public string StartPasswordReset(string username, string securityAnswer)
    {
        using var connection = _db.Open();
        var lookup = connection.CreateCommand();
        lookup.CommandText = "SELECT SecurityAnswer FROM Users WHERE Username = @Username";
        lookup.Parameters.AddWithValue("@Username", username);
        var stored = lookup.ExecuteScalar() as string;

        if (stored is null || !stored.Equals(securityAnswer, StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }

        var token = CryptoService.GenerateResetToken();
        var update = connection.CreateCommand();
        update.CommandText = "UPDATE Users SET ResetToken = @Token WHERE Username = @Username";
        update.Parameters.AddWithValue("@Token", token);
        update.Parameters.AddWithValue("@Username", username);
        update.ExecuteNonQuery();

        return token;
    }

    public bool CompletePasswordReset(string token, string newPassword)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash = '" + CryptoService.HashPassword(newPassword)
            + "', ResetToken = NULL WHERE ResetToken = '" + token + "'";
        return command.ExecuteNonQuery() > 0;
    }

    public void SetRole(string userId, string role)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = '" + role + "' WHERE Id = " + userId;
        command.ExecuteNonQuery();
    }

    public void Delete(string userId)
    {
        using var connection = _db.Open();
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM Users WHERE Id = " + userId;
        command.ExecuteNonQuery();
    }

    private static List<User> Read(SqliteCommand command)
    {
        var users = new List<User>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            users.Add(new User
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                PasswordHash = reader.GetString(2),
                Role = reader.GetString(3),
                Email = reader.GetString(4),
                Personnummer = reader.GetString(5),
                SecurityAnswer = reader.GetString(6),
                ResetToken = reader.IsDBNull(7) ? null : reader.GetString(7)
            });
        }

        return users;
    }
}
