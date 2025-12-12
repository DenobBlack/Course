<Window x:Class="CryptoChat.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Messenger" Height="350" Width="500">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBox x:Name="ChatBox" IsReadOnly="True" TextWrapping="Wrap" />

        <StackPanel Grid.Row="1" Orientation="Horizontal">
            <TextBox x:Name="InputBox" Width="350"/>
            <Button Content="Send" Width="80" Margin="10,0,0,0" Click="Send_Click"/>
        </StackPanel>
    </Grid>
</Window>
using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Net.Sockets;
using System.Net;
using System.IO;

namespace CryptoChat
{
    public partial class MainWindow : Window
    {
        private RSACryptoServiceProvider rsaLocal;
        private RSACryptoServiceProvider rsaRemote;
        private TcpClient client;
        private TcpListener listener;

        public MainWindow()
        {
            InitializeComponent();

            rsaLocal = new RSACryptoServiceProvider(2048);
            rsaRemote = new RSACryptoServiceProvider(2048);

            listener = new TcpListener(IPAddress.Loopback, 9000);
            listener.Start();
            listener.BeginAcceptTcpClient(OnClientConnect, null);
        }

        private void OnClientConnect(IAsyncResult ar)
        {
            var c = listener.EndAcceptTcpClient(ar);
            using var stream = c.GetStream();
            using var br = new BinaryReader(stream);

            int keyLen = br.ReadInt32();
            byte[] encKey = br.ReadBytes(keyLen);

            int msgLen = br.ReadInt32();
            byte[] encMsg = br.ReadBytes(msgLen);

            byte[] aesKey = rsaLocal.Decrypt(encKey, false);
            string message = AES_Decrypt(encMsg, aesKey);

            Dispatcher.Invoke(() => ChatBox.AppendText($"Друг: {message}\n"));

            listener.BeginAcceptTcpClient(OnClientConnect, null);
        }

        private void Send_Click(object sender, RoutedEventArgs e)
        {
            string txt = InputBox.Text;
            if (string.IsNullOrEmpty(txt)) return;

            byte[] aesKey = GenerateAESKey();
            byte[] encryptedMsg = AES_Encrypt(txt, aesKey);

            byte[] encKey = rsaRemote.Encrypt(aesKey, false);

            client = new TcpClient();
            client.Connect(IPAddress.Loopback, 9000);

            using var stream = client.GetStream();
            using var bw = new BinaryWriter(stream);

            bw.Write(encKey.Length);
            bw.Write(encKey);
            bw.Write(encryptedMsg.Length);
            bw.Write(encryptedMsg);

            ChatBox.AppendText($"Я: {txt}\n");
            InputBox.Text = "";
        }

        private byte[] GenerateAESKey()
        {
            using var aes = Aes.Create();
            aes.GenerateKey();
            return aes.Key;
        }

        private byte[] AES_Encrypt(string text, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
                sw.Write(text);

            return ms.ToArray();
        }

        private string AES_Decrypt(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;

            byte[] iv = new byte[16];
            Array.Copy(data, 0, iv, 0, 16);
            aes.IV = iv;

            using var ms = new MemoryStream(data, 16, data.Length - 16);
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }
}
