using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace app.TcpOperations
{
    public class MyTcpClient
    {
        public bool IsReadyToWrite { get; set; }

        private readonly ILogger _logger;
        private readonly string _server;
        private readonly int _serverPort;
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);
        private readonly CancellationTokenSource _cancellationTokenSource = new();
        private readonly bool _useTls;
        private readonly X509Certificate2 _clientCert;
        private readonly X509Certificate2 _serverParentCert;

        private bool _isRunning;
        private bool _isExitSignaled;
        private BufferedStream _bufferedStream;

        /// <summary>
        /// Initializes a new instance of the MyTcpClient class
        /// </summary>
        /// <param name="logger">ILogger interface.</param>
        /// <param name="server">The target server host or ip.</param>
        /// <param name="serverPort">The target server port.</param>
        /// <param name="useTls">Use TLS or not.</param>
        /// <param name="clientCert">The client certificate for mutual authentication. Pass null if no mutual authentication is needed.</param>
        /// <param name="serverParentCert">The certificate used to sign the server certificate. If this is not null, this will be used to validate the server cert chain.</param>
        public MyTcpClient(ILogger logger,
                           string server,
                           int serverPort,
                           bool useTls,
                           X509Certificate2 clientCert,
                           X509Certificate2 serverParentCert)
        {
            _logger = logger;
            _server = server;
            _serverPort = serverPort;
            _useTls = useTls;
            _clientCert = clientCert;
            _serverParentCert = serverParentCert;
        }

        /// <summary>
        /// Start the client main loop to keep trying to connect and then receive until Stop() is called.
        /// If the loop is already running, this method returns immediately.
        /// This is usually called at a separate thread.
        /// </summary>
        public async Task RunAsync()
        {
            if (_isRunning)
            {
                return;
            }

            _logger.Log(LogLevel.Debug, "Starting....");

            _isRunning = true;
            _isExitSignaled = false;

            // The main loop to keep trying to connect to the server and then start receiving.
            while (!_isExitSignaled)
            {
                await HandleConnectionAttempAndReceiveAsync();
            }

            _isRunning = false;
            _logger.Log(LogLevel.Debug, "Stopped");
        }

        /// <summary>
        /// Stop the client.
        /// This will trigger the main Run thread to finish.
        /// </summary>
        public void Stop()
        {
            _isExitSignaled = true;

            try
            {
                _cancellationTokenSource.Cancel();
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }

            try
            {
                _writeSemaphore.Dispose();
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }

            try
            {
                _cancellationTokenSource.Dispose();
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
        }

        /// <summary>
        /// Write the data to the target server stream.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The offset in the buffer.</param>
        /// <param name="length">The length of data to write.</param>
        /// <returns></returns>
        public async Task WriteAsync(byte[] buffer,
                                     int offset,
                                     int length)
        {
            if (!IsReadyToWrite)
            {
                return;
            }

            // It is possible that the write is called by different threads. Thus, we use a semaphore to protect.
            await _writeSemaphore.WaitAsync(_cancellationTokenSource.Token);
            try
            {
                await _bufferedStream.WriteAsync(buffer.AsMemory(offset, length));
                await _bufferedStream.FlushAsync();
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Try connecting to the server and start receiving.
        /// </summary>
        private async Task HandleConnectionAttempAndReceiveAsync()
        {
            const int connectionAttempDelayInMilliSeconds = 1000;
            var tcpClient = new TcpClient();

            try
            {
                await tcpClient.ConnectAsync(_server, _serverPort, _cancellationTokenSource.Token);

                if (!tcpClient.Connected)
                {
                    _logger.Log(LogLevel.Warning, "Connection is not done. Retry.");
                    return;
                }

                _logger.Log(LogLevel.Debug, $"Connected to server {_server}:{_serverPort}. Start receiving...");

                await ReceiveAsync(tcpClient);
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
            finally
            {
                tcpClient.Close();
                tcpClient.Dispose();

                _logger.Log(LogLevel.Debug, "Connection finished. Retry connecting...");
                Thread.Sleep(connectionAttempDelayInMilliSeconds);
            }
        }

        /// <summary>
        /// Start the receiving loop to receive the incoming data from the server.
        /// </summary>
        /// <param name="tcpClient">The target TcpClient.</param>
        /// <returns></returns>
        private async Task ReceiveAsync(TcpClient tcpClient)
        {
            NetworkStream networkStream = null;
            SslStream sslStream = null;
            try
            {
                (networkStream, sslStream) = TcpUtilities.GetTargetStream(tcpClient, _useTls, ValidateServerCertificate);

                // Start TLS handshaking if sslStream object is obtained.
                // Let OS choose the best SSL protocol.
                // TODO: Change the SSL protocols accordingly.
                if (sslStream != null)
                {
                    var clientCertCollection = new X509Certificate2Collection();
                    if (_clientCert != null)
                    {
                        clientCertCollection.Add(_clientCert);
                    }

                    await sslStream.AuthenticateAsClientAsync(_server, clientCertificates: clientCertCollection,
                        enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: true);
                }

                if (!TcpUtilities.CheckSslStream(sslStream, (_clientCert != null)))
                {
                    throw new AuthenticationException("SSL stream is not valid");
                }

                _bufferedStream = (sslStream != null) ? new BufferedStream(sslStream) : new BufferedStream(networkStream);
                IsReadyToWrite = true;

                await ReceiveAndProcessDataAsync(networkStream, sslStream);
            }
            catch (Exception e)
            {
                var loglevel = (e is OperationCanceledException || e is SocketException || e is IOException) ?
                    LogLevel.Trace : LogLevel.Debug;
                _logger.Log(loglevel, $"{e}");
            }
            finally
            {
                IsReadyToWrite = false;
                networkStream?.Close();
                sslStream?.Close();
                _bufferedStream?.Close();
                networkStream?.Dispose();
                sslStream?.Dispose();
                _bufferedStream?.Dispose();
                _logger.Log(LogLevel.Debug, "Client stream is closded.");
            }
        }

        /// <summary>
        /// Start the loop to keep processing the incoming data from the server.
        /// </summary>
        /// <param name="networkStream">The network stream for the server.</param>
        /// <param name="sslStream">The SSL stream for the server.</param>
        /// <returns></returns>
        private async Task ReceiveAndProcessDataAsync(NetworkStream networkStream,
                                                      SslStream sslStream)
        {
            var buffer = new Byte[256];
            int len;
            if (sslStream != null)
            {
                while ((len = await sslStream.ReadAsync(buffer.AsMemory(0, buffer.Length),
                    _cancellationTokenSource.Token)) != 0 &&
                    !_isExitSignaled)
                {
                    ProcessData(buffer, len);
                }
            }
            else
            {
                while ((len = await networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length),
                    _cancellationTokenSource.Token)) != 0 &&
                    !_isExitSignaled)
                {
                    ProcessData(buffer, len);
                }
            }
        }

        /// <summary>
        /// Process the incoming data from the server.
        /// The logic in this method should be replaced with the target applicatoin data design.
        /// </summary>
        /// <param name="buffer">The incoming data buffer.</param>
        /// <param name="length">The size of the data chunk.</param>
        private void ProcessData(byte[] buffer,
                                 int length)
        {
            // Dummy processing for tutorial purpose.
            var dataString = System.Text.Encoding.ASCII.GetString(buffer, 0, length);
            _logger.Log(LogLevel.Information, $"Receives message from server: {dataString}");
        }

        /// <summary>
        /// Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="certificate">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>True if the incoming certificate is accepted.</returns>
        private bool ValidateServerCertificate(object sender,
                                               X509Certificate certificate,
                                               X509Chain chain,
                                               SslPolicyErrors sslPolicyErrors)
        {
            return TcpUtilities.ValidateCertificate(certificate, sslPolicyErrors, _serverParentCert);
        }
    }
}