using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace app.TcpOperations
{
    public class MyTcpServer
    {
        private readonly ILogger _logger;
        private readonly IPAddress _hostIp;
        private readonly int _listeningPort;
        private readonly int _maxConcurrentClients;
        private readonly List<Task> _clientTasks = new();
        private readonly ConcurrentDictionary<string, AcceptedClient> _acceptedClients = new();
        private readonly X509Certificate2 _serverCert;
        private readonly bool _clientCertificateRequired;
        private readonly X509Certificate2 _clientParentCert;

        private bool _isRunning;
        private bool _isExitSignaled;
        private TcpListener _tcpListener;

        /// <summary>
        /// Initializes a new instance of the MyTcpServer class.
        /// </summary>
        /// <param name="logger">ILogger interface.</param>
        /// <param name="hostIp">The server IP. Pass null or empty string to use all network interfaces.</param>
        /// <param name="listeningPort">The server port.</param>
        /// <param name="maxConcurrentClients">The max concurrent client listeners.</param>
        /// <param name="serverCert">The server certificate for TLS. Pass null if no TLS is needed.</param>
        /// <param name="clientCertificateRequired">Require client certificate for mutual authentication or not.</param>
        /// <param name="clientParentCert">The certificate used to sign the client certificate. If this is not null, this will be used to validate the client cert chain.</param>
        public MyTcpServer(ILogger logger,
                           string hostIp,
                           int listeningPort,
                           int maxConcurrentClients,
                           X509Certificate2 serverCert,
                           bool clientCertificateRequired,
                           X509Certificate2 clientParentCert)
        {
            _logger = logger;

            if (string.IsNullOrWhiteSpace(hostIp) ||
                !IPAddress.TryParse(hostIp, out _hostIp))
            {
                _hostIp = IPAddress.Any;
            }

            _listeningPort = listeningPort;
            _maxConcurrentClients = maxConcurrentClients;
            _serverCert = serverCert;
            _clientCertificateRequired = clientCertificateRequired;
            _clientParentCert = clientParentCert;
        }

        /// <summary>
        /// Get the client ID list from the accepted client list.
        /// </summary>
        /// <returns>The client ID list.</returns>
        public string[] GetAcceptedClients()
        {
            return _acceptedClients.Keys.ToArray();
        }

        /// <summary>
        /// Start the server main loop to keep accepting new connections until Stop() is called.
        /// If the loop is already running, this method returns immediately.
        /// This is usually called at a separate thread.
        /// </summary>
        public void Run()
        {
            if (_isRunning)
            {
                return;
            }

            _logger.Log(LogLevel.Debug, "Starting....");

            _isRunning = true;
            _isExitSignaled = false;

            try
            {
                _tcpListener = new TcpListener(_hostIp, _listeningPort);
                _tcpListener.Start();

                // The main loop to keep accepting new connections until the exit is signaled.
                while (!_isExitSignaled)
                {
                    HandleConnectionRequest();
                }
            }
            catch (SocketException e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
            finally
            {
                _tcpListener?.Stop();
                _isRunning = false;
                _logger.Log(LogLevel.Debug, "Stopped");
            }
        }

        /// <summary>
        /// Stop the server.
        /// This will trigger the main Run thread to finish.
        /// </summary>
        public void Stop()
        {
            _isExitSignaled = true;
        }

        /// <summary>
        /// Write data to the target client.
        /// </summary>
        /// <param name="clientId">The client ID.</param>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The offset in the buffer.</param>
        /// <param name="length">The length of data to write.</param>
        /// <returns></returns>
        public async Task WriteToClientAsync(string clientId,
                                             byte[] buffer,
                                             int offset,
                                             int length)
        {
            if (!_acceptedClients.TryGetValue(clientId, out var acceptedClient))
            {
                throw new InvalidOperationException($"Client {clientId} is not in accepted client list. Will not perform writing data.");
            }

            await acceptedClient.WriteAsync(buffer, offset, length);
        }

        /// <summary>
        /// Handle connection request and clean-up.
        /// This will be called in the while loop in the main Run thread.
        /// This will make sure that we have max number of threads/tasks to handle client requests.
        /// This will also make sure to clean up the finished client connection.
        /// </summary>
        private void HandleConnectionRequest()
        {
            const int waitingToCheckTaskCompletionInMilliSecond = 500;

            // Launch max number of threads/tasks to accept connection request and then process the data.
            while (_clientTasks.Count < _maxConcurrentClients)
            {
                _clientTasks.Add(Task.Run(async () =>
                {
                    await ProcessClientAsync();
                }));
            }

            // Clean up the finished client connection.
            var taskIndex = Task.WaitAny(_clientTasks.ToArray(), waitingToCheckTaskCompletionInMilliSecond);
            if (taskIndex >= 0)
            {
                _clientTasks.RemoveAt(taskIndex);
            }
        }

        /// <summary>
        /// Process the client connection request and incoming data.
        /// </summary>
        /// <returns></returns>
        private async Task ProcessClientAsync()
        {
            AcceptedClient acceptedClient = null;
            TcpClient tcpClient = null;
            NetworkStream networkStream = null;
            SslStream sslStream = null;
            BufferedStream bufferedStream = null;
            string clientId = string.Empty;

            try
            {
                // Process the connection request.
                tcpClient = await _tcpListener.AcceptTcpClientAsync();

                clientId = AcceptedClient.GetClientId(tcpClient.Client.RemoteEndPoint as IPEndPoint);

                if (!tcpClient.Connected)
                {
                    _logger.Log(LogLevel.Warning, $"Client {clientId} is not connected. Stop data processing.");
                    return;
                }

                _logger.Log(LogLevel.Debug, $"Client {clientId} is connected. Start receiving....");

                (networkStream, sslStream) = TcpUtilities.GetTargetStream(tcpClient, _serverCert != null, ValidateClientCertificate);

                // Start TLS handshaking if sslStream object is obtained.
                // Let OS choose the best SSL protocol.
                // TODO: Change the SSL protocols accordingly.
                if (sslStream != null)
                {
                    await sslStream.AuthenticateAsServerAsync(_serverCert, clientCertificateRequired: _clientCertificateRequired,
                        enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: true);
                }

                if (!TcpUtilities.CheckSslStream(sslStream, _clientCertificateRequired))
                {
                    throw new AuthenticationException("SSL stream is not valid");
                }

                // Track this client.
                bufferedStream = (sslStream != null) ? new BufferedStream(sslStream) : new BufferedStream(networkStream);
                acceptedClient = new AcceptedClient(_logger, clientId, bufferedStream);
                _acceptedClients.TryAdd(clientId, acceptedClient);

                await ReceiveAndProcessDataAsync(acceptedClient, networkStream, sslStream);
            }
            catch (Exception e)
            {
                var loglevel = (e is OperationCanceledException || e is SocketException || e is IOException) ?
                    LogLevel.Trace : LogLevel.Debug;
                _logger.Log(loglevel, $"{e}");
            }
            finally
            {
                acceptedClient?.Dispose();
                networkStream?.Close();
                sslStream?.Close();
                bufferedStream?.Close();
                tcpClient?.Close();
                networkStream?.Dispose();
                sslStream?.Dispose();
                bufferedStream?.Dispose();
                tcpClient?.Dispose();

                // Remove this from tracking.
                _acceptedClients.TryRemove(clientId, out _);

                if (_isExitSignaled)
                {
                    _logger.Log(LogLevel.Debug, $"Server is exiting. Stop connection for Client {clientId}.");
                }
                else
                {
                    _logger.Log(LogLevel.Debug, $"Client {clientId} finished connection.");
                }
            }
        }

        /// <summary>
        /// Start the loop to keep processing the incoming data from the client.
        /// </summary>
        /// <param name="acceptedClient">The client.</param>
        /// <param name="networkStream">The network stream for the client.</param>
        /// <param name="sslStream">The SSL stream for the client.</param>
        /// <returns></returns>
        private async Task ReceiveAndProcessDataAsync(AcceptedClient acceptedClient,
                                                      NetworkStream networkStream,
                                                      SslStream sslStream)
        {
            var buffer = new Byte[256];
            int len;
            if (sslStream != null)
            {
                while ((len = await sslStream.ReadAsync(buffer.AsMemory(0, buffer.Length), CancellationToken.None)) != 0 &&
                    !_isExitSignaled)
                {
                    acceptedClient.ProcessData(buffer, len);
                }
            }
            else
            {
                while ((len = await networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length), CancellationToken.None)) != 0 &&
                    !_isExitSignaled)
                {
                    acceptedClient.ProcessData(buffer, len);
                }
            }
        }

        /// <summary>
        /// Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="certificate">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>True if the incoming certificate is accepted.</returns>
        private bool ValidateClientCertificate(object sender,
                                               X509Certificate certificate,
                                               X509Chain chain,
                                               SslPolicyErrors sslPolicyErrors)
        {
            if (!_clientCertificateRequired)
            {
                return true;
            }

            return TcpUtilities.ValidateCertificate(certificate, sslPolicyErrors, _clientParentCert);
        }
    }
}