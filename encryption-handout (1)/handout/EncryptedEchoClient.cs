using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {
    //global variables 
    byte[]? aesKey;
    byte[]? aesIV;
    byte[]? hmacKey;
    byte[]? rsaKey;
    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    /// <inheritdoc />
    /*
    * ProcessServerHello function recieves RSA public key sent by server 
    * 
    *
    * Param data - the message is the RSA public key from server
    *
    * Return nothing
    */
    public override void ProcessServerHello(string message) {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        Console.WriteLine("In ProcessServer");
        Console.WriteLine("Recieved message: " + message);
        // convert base 64 to a array 
        rsaKey = Convert.FromBase64String(message);
        if(rsaKey == null || rsaKey.Length == 0 ){
             throw new Exception("An error occurred. there is no rsa key.");
        }
        // Throw a CryptographicException if the received key is invalid.
    }
    /*
    * AESEncrypt function generates an AES key and encrypts the given message 
    * 
    *
    * Param data - the message in byte form 
    * Param aeskey - out is stated so that the values will be changed within function but returned after function set the aes key
    * Param aesIV - set the aes initialization vector 
    * Return returns the message after being encrypted with AES key 
    */
    private static byte[] AESEncrypt(byte[] data, out byte[] aesKey, out byte[] aesIV){
        // todo: Step 1: Encrypt the input using hybrid encryption.
        
        // Generate a new AES key
        using (Aes aes = Aes.Create())
        {
            //set mode and padding 
            // Encrypt using AES with CBC mode and PKCS7 padding.
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Use a different key each time.
            // Generate a new AES key and IV each time
            aes.GenerateKey();
            aes.GenerateIV();

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                aesKey = aes.Key;
                aesIV = aes.IV;
                //print the encrypted data in base64 string 
                Console.WriteLine("Encrypted data (Base64): " + Convert.ToBase64String(encryptedData));
                // Print the AES key and IV
                Console.WriteLine("Generated AES Key (Base64): " + Convert.ToBase64String(aes.Key));
                Console.WriteLine("Generated AES IV (Base64): " + Convert.ToBase64String(aes.IV));
                return encryptedData;
            }
           
        }
       
    }
    /*
    * HmacEncrypt function generates an HMAC of the message 
    * Makes a call to generate random key 
    *
    * Param data - the message in byte form 
    *
    * Return returns the message after being hashed with hmac
    */
    // todo: Step 2: Generate an HMAC of the message.
    private byte[] HmacEncrypt(byte[] data)
    {
        Console.WriteLine("In HmacEncrypt");
        // Use a different key each time.
        hmacKey = GenerateRandomKey();
        // Use the SHA256 variant of HMAC.
        using HMACSHA256 hmac = new HMACSHA256(hmacKey);
        // Compute the HMAC
        return hmac.ComputeHash(data);
    }
    // create random key 
    private static byte[] GenerateRandomKey()
    {
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] key = new byte[32]; 
        rng.GetBytes(key);
        Console.WriteLine("Generated Hmac key (Base64): " + Convert.ToBase64String(key));
        return key;
    }
    // Encrypt using the OAEP padding scheme with SHA256.
    private void EncryptKeys(out byte[] encryptedAesKey, out byte[] encryptedHmacKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportRSAPublicKey(rsaKey, out _);
            if (aesKey != null)
            {
                encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
            }
            else
            {
                throw new ArgumentNullException(nameof(aesKey), "AES key cannot be null.");
            }

            if (hmacKey != null)
            {
                encryptedHmacKey = rsa.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);
            }
            else
            {
                throw new ArgumentNullException(nameof(hmacKey), "HMAC key cannot be null.");
            }
            Console.WriteLine("encrypted aes key (Base64): " + Convert.ToBase64String(encryptedAesKey));
            Console.WriteLine("encrypted Hmac key (Base64): " + Convert.ToBase64String(encryptedHmacKey));
        }
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        Console.WriteLine("In TransformOutgoingMessage");
        Console.WriteLine("input: " + input);
        byte[] data = Settings.Encoding.GetBytes(input);
        Console.WriteLine("data: " + BitConverter.ToString(data).Replace("-", ""));

        byte[] aesEncryptMessage= AESEncrypt(data, out aesKey, out aesIV);
        Console.WriteLine("Generated AES Key (Base64): " + Convert.ToBase64String(aesKey));
        Console.WriteLine("Generated AES IV (Base64): " + Convert.ToBase64String(aesIV));
        Console.WriteLine("data AFTER: " + BitConverter.ToString(data).Replace("-", ""));
        byte[] hmac = HmacEncrypt(data);
        Console.WriteLine("Hmac Encryption of message (Base64): " + Convert.ToBase64String(hmac));
        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        EncryptKeys(out byte[] encryptedAesKey, out byte[] encryptedHmacKey);
        Console.WriteLine("encrypted aes key (Base64): " + Convert.ToBase64String(encryptedAesKey));
        Console.WriteLine("encrypted Hmac key (Base64): " + Convert.ToBase64String(encryptedHmacKey));
        

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);

        return input;
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        // var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.

        // todo: Step 3: Return the message from the server.
        // return Settings.Encoding.GetString(signedMessage.Message);
        return input;
    }
}