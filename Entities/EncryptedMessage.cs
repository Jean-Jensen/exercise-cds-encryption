public class EncryptedMessage
{
    public required byte[] Salt { get; set; }
    public required byte[] Nonce { get; set; }
    public required byte[] CipherText { get; set; }
    public required byte[] Tag { get; set; }

    public EncryptedMessage()
    {
        
    }

    public EncryptedMessage(byte[] salt, byte[] nonce, byte[] cipherText, byte[] tag)
    {
        Salt = salt;
        Nonce = nonce;
        CipherText = cipherText;
        Tag = tag;
    }
}
