using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;

namespace cds_encryption.Controllers;

[ApiController]
[Route("[controller]")]
public class SecretController : ControllerBase
{
    private readonly ILogger<SecretController> _logger;
    
    
    public SecretController(ILogger<SecretController> logger)
    {
        _logger = logger;
    }

    [HttpPost]
    public ActionResult Post([FromBody] SaveSecretMessageRequest request)
    {
        
        var salt = RandomNumberGenerator.GetBytes(256 / 8);

        var key = KeyDerivation.Pbkdf2(
            request.Password,
            salt,
            KeyDerivationPrf.HMACSHA256,
            iterationCount: 600_000,
            numBytesRequested: 256 /8
            );
        
        var aes = new AesGcm(key);
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; //MaxSize = 12
        RandomNumberGenerator.Fill(nonce);

        var plaintextBytes = Encoding.UTF8.GetBytes(request.Message); 
        var ciphertext = new byte[request.Message.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
        
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        EncryptedMessage enMes = new EncryptedMessage {Salt = salt, Nonce = nonce, CipherText = ciphertext, Tag = tag};
        
        string text = JsonSerializer.Serialize(enMes);

        string docPath = "save files";

        using (StreamWriter outputfile = new StreamWriter(Path.Combine(docPath, "output.txt")))
        {
            outputfile.WriteLine(text);
        }
        
        /*
        throw new NotImplementedException(
            @"
            TODO:
            1. Derive encryption key from password
            2. Encrypt message using derived key
            3. Save encrypted message to a file
            "
        );
        */

        return Ok(text);

    }

    [HttpGet]
    public ActionResult<String> Get([FromQuery] ReadSecretMessageRequest request)
    {
        throw new NotImplementedException(
            @"
            TODO:
            1. Read encrypted message from file
            2. Derive encryption key from password
            3. Decrypt message using derived key
            4. Return decrypted message
          "
        );
    }
}
