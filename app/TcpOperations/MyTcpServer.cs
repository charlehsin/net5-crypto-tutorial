using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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

        private bool _isRunning;
        private bool _isExitSignaled;
        private TcpListener _tcpListener;

        /// <summary>
        /// Initializes a new instance of the MyTcpServer class.
        /// </summary>
        /// <param name="logger">ILogger interface</param>
        /// <param name="hostIp">The server IP. Pass null or empty string to use all network interfaces.</param>
        /// <param name="listeningPort">The server port</param>
        /// <param name="maxConcurrentClients">The max concurrent client listeners</param>
        public MyTcpServer(ILogger logger, string hostIp, int listeningPort,
            int maxConcurrentClients)
        {
            _logger = logger;

            if (string.IsNullOrWhiteSpace(hostIp) ||
                !IPAddress.TryParse(hostIp, out _hostIp))
            {
                _hostIp = IPAddress.Any;
            }

            _listeningPort = listeningPort;
            _maxConcurrentClients = maxConcurrentClients;
        }

        /// <summary>
        /// Get the list of client ID from the accepted client list.
        /// </summary>
        /// <returns>The client Id list</returns>
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
        /// <param name="clientId">The client ID</param>
        /// <param name="buffer">The data buffer</param>
        /// <param name="offset">The offset in the buffer</param>
        /// <param name="length">The length of data to write</param>
        /// <returns></returns>
        public async Task WriteToClientAsync(string clientId, byte[] buffer, int offset, int length)
        {
            if (!_acceptedClients.TryGetValue(clientId, out var acceptedClient))
            {
                _logger.Log(LogLevel.Warning, $"Client {clientId} is not in accepted client list. Will not perform writing data.");
                return;
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

                networkStream = tcpClient.GetStream();

                // Track this client.
                acceptedClient = new AcceptedClient(_logger, clientId, networkStream);
                _acceptedClients.TryAdd(clientId, acceptedClient);

                // Start the loop to keep processing the incoming data from the client.
                var buffer = new Byte[256];
                int len;
                while ((len = await networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length), CancellationToken.None)) != 0 &&
                    !_isExitSignaled)
                {
                    acceptedClient.ProcessData(buffer, len);
                }

                if (_isExitSignaled)
                {
                    _logger.Log(LogLevel.Debug, $"Server is exiting. Stop connection for Client {clientId}.");
                }
                else
                {
                    _logger.Log(LogLevel.Debug, $"Client {clientId} finished connection.");
                }
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
            finally
            {
                acceptedClient?.Dispose();
                networkStream?.Close();
                tcpClient?.Close();

                // Remove this from tracking.
                _acceptedClients.TryRemove(clientId, out _);
            }
        }
    }
}