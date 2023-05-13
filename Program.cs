using System.Security.Cryptography;

internal class Program
{
    static void Main()
    {
        string plaintext = "";
        long generateText, encrypt, decrypt, start, end;
        while (true)
        {
            Console.Write("Введите размер тестируемой строки (0, {0}): ", UInt16.MaxValue);
            string input = Console.ReadLine();
            try {
                int size = Convert.ToUInt16(input);
                start = DateTime.Now.Ticks;
                plaintext = GenerateRandomString(size); // текст, который мы хотим зашифровать
                end = DateTime.Now.Ticks;
                generateText = end - start;
                break;
            }
            catch (FormatException ex) {
                Console.WriteLine("Введите число");
            }
            catch (OverflowException ex) {
                Console.WriteLine("Введите число входящие в данные рамки (0, {0})", UInt16.MaxValue);
            }
        }

        // генерация случайного ключа и вектора инициализации
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();
            key = aes.Key;
            iv = aes.IV;
        }
        
        start = DateTime.Now.Ticks;
        byte[] encrypted = EncryptStringToBytes_Aes(plaintext, key, iv); // зашифрованный текст
        end = DateTime.Now.Ticks;
        
        encrypt = end - start;

        start = DateTime.Now.Ticks;
        string decrypted = DecryptStringFromBytes_Aes(encrypted, key, iv); // расшифрованный текст
        end = DateTime.Now.Ticks;
        
        decrypt = end - start;

        Console.WriteLine("Генерация текста: {0}", generateText);
        Console.WriteLine("Зашифровка: {0}", encrypt);
        Console.WriteLine("Расшифровка: {0}", decrypt);
        //Console.WriteLine("Расшифрованый текст: {0}", decrypted);
        Console.ReadKey();
    }

    public static string GenerateRandomString(int length)
    {
        if (length < 0) throw new OverflowException();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var random = new Random();
        return new string(Enumerable.Repeat(chars, length)
          .Select(s => s[random.Next(s.Length)]).ToArray());
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        // Проверка аргументов
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        byte[] encrypted;

        // Создание объекта AES с указанным ключом и вектором инициализации
        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;

            // Создание объекта для шифрования
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            // Создание потока для записи зашифрованных данных
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // Создание объекта для записи зашифрованных данных в поток
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    // Запись зашифрованных данных в поток
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        // Возвращение зашифрованных данных
        return encrypted;
    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        // Проверка аргументов
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        string plaintext = null;

        // Создание объекта AES с указанным ключом и вектором инициализации
        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;
            
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            // Создание потока для чтения зашифрованных данных
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                // Создание объекта для чтения зашифрованных данных из потока
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    // Чтение расшифрованных данных из потока
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        // Возвращение расшифрованного текста
        return plaintext;
    }

}