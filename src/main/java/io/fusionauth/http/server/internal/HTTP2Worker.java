/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package io.fusionauth.http.server.internal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import io.fusionauth.http.HTTPValues.Protocols;
import io.fusionauth.http.http2.HPACKHeader;
import io.fusionauth.http.http2.HTTP2Connection;
import io.fusionauth.http.http2.HTTP2ErrorCode;
import io.fusionauth.http.http2.HTTP2Exception;
import io.fusionauth.http.http2.HTTP2Settings;
import io.fusionauth.http.http2.HTTP2Stream;
import io.fusionauth.http.http2.HTTP2StreamState;
import io.fusionauth.http.log.Logger;
import io.fusionauth.http.server.HTTPListenerConfiguration;
import io.fusionauth.http.server.HTTPRequest;
import io.fusionauth.http.server.HTTPResponse;
import io.fusionauth.http.server.HTTPServerConfiguration;
import io.fusionauth.http.server.Instrumenter;

/**
 * Handles an HTTP/2 connection: reads multiplexed streams and dispatches each completed request
 * to the configured {@link io.fusionauth.http.server.HTTPHandler} on a virtual thread.
 */
public class HTTP2Worker implements Runnable {
  private final Socket socket;
  private final HTTPServerConfiguration configuration;
  private final Instrumenter instrumenter;
  private final HTTPListenerConfiguration listener;
  private final InputStream inputStream;
  private final OutputStream outputStream;
  private final Logger logger;
  private final Map<Integer, AtomicBoolean> dispatched = new ConcurrentHashMap<>();
  private final ExecutorService handlers = Executors.newVirtualThreadPerTaskExecutor();

  public HTTP2Worker(Socket socket, HTTPServerConfiguration configuration, Instrumenter instrumenter,
                    HTTPListenerConfiguration listener, InputStream inputStream, OutputStream outputStream) {
    this.socket = socket;
    this.configuration = configuration;
    this.instrumenter = instrumenter;
    this.listener = listener;
    this.inputStream = inputStream;
    this.outputStream = outputStream;
    this.logger = configuration.getLoggerFactory().getLogger(HTTP2Worker.class);
  }

  @Override
  public void run() {
    HTTP2Settings settings = new HTTP2Settings();
    settings.setEnablePush(0);
    settings.setMaxConcurrentStreams(100);
    try (HTTP2Connection connection = new HTTP2Connection(inputStream, outputStream, true, settings)) {
      if (instrumenter != null) {
        instrumenter.workerStarted();
      }
      connection.setOnHeadersComplete(stream -> {
        AtomicBoolean once = dispatched.computeIfAbsent(stream.id, id -> new AtomicBoolean(false));
        if (once.compareAndSet(false, true)) {
          handlers.execute(() -> handleStream(connection, stream));
        }
      });
      connection.handshake();
      while (!connection.isClosed() && !Thread.currentThread().isInterrupted()) {
        if (!connection.processOneFrame()) {
          break;
        }
      }
    } catch (HTTP2Exception e) {
      logger.debug("[{}] HTTP/2 error [{}]: {}", Thread.currentThread().threadId(), e.errorCode, e.getMessage());
    } catch (IOException e) {
      logger.debug("[{}] HTTP/2 IO error: {}", Thread.currentThread().threadId(), e.getMessage());
    } catch (Throwable t) {
      logger.debug(String.format("[%s] HTTP/2 unexpected error", Thread.currentThread().threadId()), t);
    } finally {
      handlers.shutdownNow();
      try {
        socket.close();
      } catch (IOException ignore) {
      }
      if (instrumenter != null) {
        instrumenter.workerStopped();
      }
    }
  }

  private void handleStream(HTTP2Connection connection, HTTP2Stream stream) {
    try {
      // Wait briefly for end-stream / body if headers arrived without END_STREAM
      if (!stream.isEndStreamReceived()) {
        stream.awaitEndStream(30, java.util.concurrent.TimeUnit.SECONDS);
      }

      List<HPACKHeader> headers = stream.getHeaders();
      String method = null;
      String path = "/";
      String scheme = listener.isTLS() ? "https" : "http";
      String authority = null;
      List<HPACKHeader> regular = new ArrayList<>();
      for (HPACKHeader h : headers) {
        switch (h.name) {
          case ":method" -> method = h.value;
          case ":path" -> path = h.value;
          case ":scheme" -> scheme = h.value;
          case ":authority" -> authority = h.value;
          default -> {
            if (!h.name.startsWith(":")) {
              regular.add(h);
            }
          }
        }
      }
      if (method == null) {
        connection.goAway(HTTP2ErrorCode.PROTOCOL_ERROR, "missing :method");
        return;
      }

      String host = authority != null ? authority : "localhost";
      int port = listener.getPort();
      int colon = host.lastIndexOf(':');
      if (colon > 0 && host.indexOf(']') < colon) {
        try {
          port = Integer.parseInt(host.substring(colon + 1));
          host = host.substring(0, colon);
        } catch (NumberFormatException ignore) {
        }
      }

      HTTPRequest request = new HTTPRequest(configuration.getContextPath(), scheme, port,
          socket.getInetAddress().getHostAddress());
      request.setMethod(io.fusionauth.http.HTTPMethod.of(method));
      request.setPath(path); // setPath parses query string when present
      request.setProtocol(Protocols.HTTTP2);
      request.setHeader("Host", authority != null ? authority : host);
      for (HPACKHeader h : regular) {
        request.setHeader(h.name, h.value);
      }

      byte[] body = stream.getData();
      request.setInputStream(new ByteArrayInputStream(body));
      if (body.length > 0 && request.getHeader("content-length") == null) {
        request.setHeader("content-length", Integer.toString(body.length));
      }

      if (instrumenter != null) {
        instrumenter.acceptedRequest();
      }

      HTTPResponse response = new HTTPResponse();
      ByteArrayOutputStream responseBody = new ByteArrayOutputStream();
      response.setOutputStream(responseBody);

      try {
        configuration.getHandler().handle(request, response);
      } finally {
        var multiPartProcessor = request.getMultiPartStreamProcessor();
        if (multiPartProcessor.getMultiPartConfiguration().isDeleteTemporaryFiles()) {
          var fileManager = multiPartProcessor.getMultipartFileManager();
          for (var file : fileManager.getTemporaryFiles()) {
            try {
              Files.deleteIfExists(file);
            } catch (Exception e) {
              logger.error("Unable to delete temporary file. [" + file + "]", e);
            }
          }
        }
      }

      // Ensure body is flushed
      try {
        response.getOutputStream().close();
      } catch (Exception ignore) {
      }

      List<HPACKHeader> responseHeaders = new ArrayList<>();
      int status = response.getStatus();
      if (status <= 0) {
        status = 200;
      }
      responseHeaders.add(new HPACKHeader(":status", Integer.toString(status)));
      boolean hasContentLength = false;
      for (var entry : response.getHeadersMap().entrySet()) {
        String name = entry.getKey().toLowerCase(Locale.ROOT);
        if (name.equals("connection") || name.equals("transfer-encoding") || name.equals("keep-alive")
            || name.equals("upgrade") || name.equals("proxy-connection")) {
          continue; // forbidden in HTTP/2
        }
        for (String value : entry.getValue()) {
          responseHeaders.add(new HPACKHeader(name, value));
          if (name.equals("content-length")) {
            hasContentLength = true;
          }
        }
      }
      byte[] respBytes = responseBody.toByteArray();
      if (!hasContentLength) {
        responseHeaders.add(new HPACKHeader("content-length", Integer.toString(respBytes.length)));
      }

      synchronized (connection) {
        connection.sendHeaders(stream, responseHeaders, respBytes.length == 0);
        if (respBytes.length > 0) {
          connection.sendData(stream, respBytes, true);
        }
        stream.setState(HTTP2StreamState.CLOSED);
      }
    } catch (Exception e) {
      logger.debug(String.format("[%s] Error handling HTTP/2 stream %d", Thread.currentThread().threadId(), stream.id), e);
      try {
        List<HPACKHeader> err = List.of(new HPACKHeader(":status", "500"));
        synchronized (connection) {
          connection.sendHeaders(stream, err, true);
        }
      } catch (IOException ignore) {
      }
    }
  }
}
