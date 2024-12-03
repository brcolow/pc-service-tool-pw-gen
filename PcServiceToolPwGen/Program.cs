using System.Security.Cryptography;

class Program
{
  static readonly char[] base36Map;

  static Program()
  {
    base36Map = new char[36];
    InitBase36Map();
  }

  static void Main(string[] args)
  {
    TryDecodePassword("LOmi83NMMIb2//Yh9fXyDg");
    string userID = "HYSTER";
    string generatedPassword = GeneratePassword(userID, Brand.Hyster, UserType.Development);
    Console.WriteLine("Your username is: " + userID + "\r\nYour generated password is:\r\n" + generatedPassword);
    TryDecodePassword(generatedPassword);
  }

  static string GeneratePassword(string userID, Brand brand, UserType userType)
  {
    byte[] outputBuffer = new byte[16];

    // userid
    // Base36 decode the userID
    byte[] userIDBytes = ConvertBase36StringToBytes("HYSTER");
    outputBuffer[0] = userIDBytes[0];
    outputBuffer[1] = userIDBytes[1];
    outputBuffer[2] = userIDBytes[2];
    outputBuffer[3] = userIDBytes[3];
    outputBuffer[4] = userIDBytes[4];
    outputBuffer[5] = userIDBytes[5];

    int accessLevelValue = (int)AccessLevel.Development;
    accessLevelValue &= 0b111;  // Mask the lower 3 bits
    // outputBuffer[5] &= 0b11100011;  // Mask to clear bits 4, 5, 6 (11100011 leaves 4,5,6 clear)
    outputBuffer[5] |= (byte)(accessLevelValue << 4);  // Shift left by 4 and OR to set bits 4,5,6

    // Convert the timestamp to the required byte array format
    DateTime expirationDate = DateTime.Now.AddYears(5);
    long targetTimestamp = expirationDate.Ticks;

    // Assign the timestamp bytes to the outputBuffer
    outputBuffer[9] = (byte)((targetTimestamp >> 56) & 0xFF);
    outputBuffer[8] = (byte)((targetTimestamp >> 48) & 0xFF);
    outputBuffer[7] = (byte)((targetTimestamp >> 40) & 0xFF);
    outputBuffer[6] = (byte)((targetTimestamp >> 32) & 0xFF);
    // Major version
    outputBuffer[10] = 5;
    // Minor version
    outputBuffer[11] = 1;

    byte brandValue = (byte)brand;
    byte userTypeValue = (byte)((int)userType << 4);
    byte combinedValue = (byte)(brandValue | userTypeValue);
    outputBuffer[12] = combinedValue;

    // Now we need to AES encrypt with the key and iv (128-bit block size - although I think we only use 96 bits as 12*8 = 96).
    byte[] key = [22, 210, 29, 30, 134, 215, 228, 40, 196, 153, 254, 103, 184, 52, 88, 201];
    byte[] iv = [128, 214, 58, 190, 150, 225, 47, 176, 184, 252, 245, 124, 237, 239, 20, 93];
    byte[] encryptedBytes;
    string base64EncodedEncryptedBytes;
    using (Aes aes = Aes.Create())
    {
      aes.Key = key;
      aes.IV = iv;
      aes.Padding = PaddingMode.None;

      ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
      using MemoryStream msEncrypt = new();
      using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
      csEncrypt.Write(outputBuffer, 0, outputBuffer.Length);
      csEncrypt.FlushFinalBlock();
      encryptedBytes = msEncrypt.ToArray();
      base64EncodedEncryptedBytes = Convert.ToBase64String(encryptedBytes);
    }

    if (base64EncodedEncryptedBytes.EndsWith("=="))
    {
      // Strip off the Base64 padding as it gets added back manually when decoding password.
      base64EncodedEncryptedBytes = base64EncodedEncryptedBytes[..^2];
    }

    return base64EncodedEncryptedBytes;
  }

  public static byte[] ConvertBase36StringToBytes(string base36String)
  {
    long decimalValue = 0;
    int power = 0;

    foreach (char c in base36String)
    {
      int digitValue = char.IsDigit(c) ? c - '0' : c - 'A' + 10;
      decimalValue += digitValue * (long)Math.Pow(36, power);
      power++;
    }

    return BitConverter.GetBytes(decimalValue);
  }

  static void InitBase36Map()
  {
    for (int index = 0; index < 10; ++index)
      base36Map[index] = (char)(index + 48);
    for (int index = 10; index < 36; ++index)
      base36Map[index] = (char)(index + 55);
  }

  static string ConvertBytesToBase36String(byte[] b)
  {
    // Pad the byte array with zeros if it has less than 8 bytes (CODE ADDED BY ME)
    if (b.Length < 8)
    {
      byte[] paddedBytes = new byte[8]; // Create an 8-byte array
      Array.Copy(b, 0, paddedBytes, 8 - b.Length, b.Length); // Copy the original bytes to the end of the new array
      b = paddedBytes; // Use the padded array
    }

    long int64 = BitConverter.ToInt64(b, 0);
    string base36String = "";
    while (int64 > 0L)
    {
      long index = int64 % 36L;
      int64 /= 36L;
      base36String += base36Map[index].ToString();
    }
    return base36String;
  }

  static bool TryDecodePassword(string rawPassword)
  {
    try
    {
      byte[] outputBuffer = new byte[16];
      byte[] inputBuffer = Convert.FromBase64String(rawPassword + "=="); // Needs 2 padding chars which means it's a multiple of 4. rawPassword is 14 bytes + 2 padding = 16 which is a multiple of 4.
      byte[] key = [22, 210, 29, 30, 134, 215, 228, 40, 196, 153, 254, 103, 184, 52, 88, 201];
      byte[] iv = [128, 214, 58, 190, 150, 225, 47, 176, 184, 252, 245, 124, 237, 239, 20, 93];
      Aes aes = Aes.Create();
      aes.BlockSize = 128;
      aes.Key = key;
      aes.IV = iv;
      aes.Padding = PaddingMode.None;
      ICryptoTransform decryptor = aes.CreateDecryptor();
      int secondTime = decryptor.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0);
      byte[] userid = new byte[8];
      for (int index = 0; index < 6; ++index)
      {
        userid[index] = outputBuffer[index];
      }
      userid[5] &= 15; // 00001111

      string userID = ConvertBytesToBase36String(userid);
      AccessLevel access = (AccessLevel)(outputBuffer[5] >> 4 & 7);
      DateTime expDate = new((long)((uint)(outputBuffer[9] << 24 | outputBuffer[8] << 16 | outputBuffer[7] << 8) | outputBuffer[6]) << 32);
      decimal majorVersion = outputBuffer[10];
      decimal minorVersion = outputBuffer[11];
      Brand brand = (Brand)(outputBuffer[12] & 7);
      UserType userType = (UserType)(outputBuffer[12] >> 4 & 7);
      Console.WriteLine($"Decoded password: userid = {userID}, access = {access}, expDate = {expDate}, majorVer = {majorVersion}, minorVer = {minorVersion}, brand = {brand}, userType = {userType}");
      return true;
    }
    catch (Exception ex)
    {
      Console.Error.WriteLine(ex.Message);
      return false;
    }
  }

  enum AccessLevel
  {
    Diagnostic,
    Service,
    Programming,
    Development,
    Customer,
    Reserved1,
    Reserved2,
    Reserved3,
  }

  enum Brand
  {
    Hyster,
    Yale,
    Utilev,
    Generic,
    Customer,
    Reserved1,
    Reserved2,
    Reserved3,
  }

  enum UserType
  {
    Development,
    Service,
    Customer1,
    Customer2,
    Customer3,
    Reserved1,
    Reserved2,
    Reserved3,
  }
}
