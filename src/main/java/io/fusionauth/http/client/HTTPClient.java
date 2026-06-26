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
package io.fusionauth.http.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import io.fusionauth.http.HTTPValues.Protocols;
import io.fusionauth.http.http2.HPACKHeader;
import io.fusionauth.http.http2.HTTP2Connection;
import io.fusionauth.http.http2.HTTP2Settings;
import io.fusionauth.http.http2.HTTP2Stream;
import io.fusionauth.http.security.SecurityTools;

/**
 * Minimal HTTP client with HTTP/1.1 and HTTP/2 support (h2 over TLS via ALPN, or h2c prior knowledge on cleartext).
 */
public class HTTPClient implements AutoCloseable {
  public enum Version {
    HTTP_1_1,
    HTTP_2,
    /** Prefer HTTP/2 (ALPN or prior knowledge), fall back is not automatic for cleartext. */
    PREFER_HTTP_2
  }

  private Duration connectTimeout = Duration.ofSeconds(10);
  private Duration readTimeout = Duration.ofSeconds(30);
  private Version version = Version.PREFER_HTTP_2;
  private Certificate[] trustCertificates;
  private boolean priorKnowledgeH2c;
  private boolean disableHostnameVerification;

  public HTTPClient withConnectTimeout(Duration connectTimeout) {
    this.connectTimeout = connectTimeout;
    return this;
  }

  public HTTPClient withReadTimeout(Duration readTimeout) {
    this.readTimeout = readTimeout;
    return this;
  }

  public HTTPClient withVersion(Version version) {
    this.version = version;
    return this;
  }

  /**
   * Trust a specific server certificate (typical for self-signed test certs).
   */
  public HTTPClient withTrustCertificate(Certificate certificate) {
    this.trustCertificates = new Certificate[]{certificate};
    return this;
  }

  /**
   * Trust a certificate chain for outbound TLS.
   */
  public HTTPClient withTrustCertificates(Certificate... certificates) {
    this.trustCertificates = certificates;
    return this;
  }

  public HTTPClient withDisableHostnameVerification(boolean disable) {
    this.disableHostnameVerification = disable;
    return this;
  }

  /**
   * Use HTTP/2 prior knowledge on cleartext connections (h2c without upgrade).
   */
  public HTTPClient withPriorKnowledgeH2c(boolean priorKnowledgeH2c) {
    this.priorKnowledgeH2c = priorKnowledgeH2c;
    return this;
  }

  public HTTPClientResponse send(HTTPClientRequest request) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(request, "request");
    URI uri = request.getUri();
    boolean tls = "https".equalsIgnoreCase(uri.getScheme());
    String host = uri.getHost();
    int port = uri.getPort() > 0 ? uri.getPort() : (tls ? 443 : 80);
    String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    if (uri.getRawQuery() != null) {
      path = path + "?" + uri.getRawQuery();
    }

    boolean useHttp2 = version == Version.HTTP_2
        || version == Version.PREFER_HTTP_2 && (tls || priorKnowledgeH2c);

    if (useHttp2) {
      return sendHttp2(request, uri, tls, host, port, path);
    }
    return sendHttp11(request, uri, tls, host, port, path);
  }

  private HTTPClientResponse sendHttp2(HTTPClientRequest request, URI uri, boolean tls, String host, int port, String path)
      throws IOException, GeneralSecurityException {
    Socket socket = connect(tls, host, port, true);
    try {
      InputStream in = socket.getInputStream();
      OutputStream out = socket.getOutputStream();
      HTTP2Settings settings = new HTTP2Settings();
      settings.setEnablePush(0);
      try (HTTP2Connection connection = new HTTP2Connection(in, out, false, settings)) {
        connection.handshake();
        // Read server SETTINGS (handler ACKs automatically)
        connection.processOneFrame();

        HTTP2Stream stream = connection.openClientStream();
        List<HPACKHeader> headers = new ArrayList<>();
        headers.add(new HPACKHeader(":method", request.getMethod()));
        headers.add(new HPACKHeader(":scheme", uri.getScheme().toLowerCase(Locale.ROOT)));
        headers.add(new HPACKHeader(":authority", authority(host, port, tls)));
        headers.add(new HPACKHeader(":path", path));
        for (Map.Entry<String, List<String>> e : request.getHeaders().entrySet()) {
          String name = e.getKey().toLowerCase(Locale.ROOT);
          if (name.equals("connection") || name.equals("transfer-encoding") || name.equals("host")
              || name.equals("keep-alive") || name.equals("upgrade") || name.equals("proxy-connection")) {
            continue;
          }
          for (String value : e.getValue()) {
            headers.add(new HPACKHeader(name, value));
          }
        }
        byte[] body = request.getBody() == null ? new byte[0] : request.getBody();
        if (body.length > 0 && !request.getHeaders().containsKey("content-length")) {
          headers.add(new HPACKHeader("content-length", Integer.toString(body.length)));
        }
        connection.sendHeaders(stream, headers, body.length == 0);
        if (body.length > 0) {
          connection.sendData(stream, body, true);
        }

        // Read until response headers + end stream for this stream
        long deadline = System.nanoTime() + readTimeout.toNanos();
        while (!stream.isHeadersReceived() || !stream.isEndStreamReceived()) {
          if (System.nanoTime() > deadline) {
            throw new IOException("Timed out waiting for HTTP/2 response");
          }
          if (!connection.processOneFrame()) {
            break;
          }
        }
        try {
          if (!stream.awaitHeaders(1, TimeUnit.SECONDS)) {
            throw new IOException("No HTTP/2 response headers");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IOException("Interrupted waiting for HTTP/2 headers", e);
        }

        int status = 0;
        Map<String, List<String>> responseHeaders = new LinkedHashMap<>();
        for (HPACKHeader h : stream.getHeaders()) {
          if (h.name.equals(":status")) {
            status = Integer.parseInt(h.value);
          } else if (!h.name.startsWith(":")) {
            responseHeaders.computeIfAbsent(h.name, k -> new ArrayList<>()).add(h.value);
          }
        }
        return new HTTPClientResponse(status, responseHeaders, stream.getData(), Protocols.HTTTP2);
      }
    } finally {
      try {
        socket.close();
      } catch (IOException ignore) {
      }
    }
  }

  private HTTPClientResponse sendHttp11(HTTPClientRequest request, URI uri, boolean tls, String host, int port, String path)
      throws IOException, GeneralSecurityException {
    Socket socket = connect(tls, host, port, false);
    try {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();
      StringBuilder preamble = new StringBuilder();
      preamble.append(request.getMethod()).append(' ').append(path).append(" HTTP/1.1\r\n");
      preamble.append("Host: ").append(authority(host, port, tls)).append("\r\n");
      preamble.append("Connection: close\r\n");
      byte[] body = request.getBody() == null ? new byte[0] : request.getBody();
      boolean hasCL = false;
      for (Map.Entry<String, List<String>> e : request.getHeaders().entrySet()) {
        for (String value : e.getValue()) {
          preamble.append(e.getKey()).append(": ").append(value).append("\r\n");
          if (e.getKey().equalsIgnoreCase("content-length")) {
            hasCL = true;
          }
        }
      }
      if (body.length > 0 && !hasCL) {
        preamble.append("Content-Length: ").append(body.length).append("\r\n");
      }
      preamble.append("\r\n");
      out.write(preamble.toString().getBytes(StandardCharsets.US_ASCII));
      if (body.length > 0) {
        out.write(body);
      }
      out.flush();

      ByteArrayOutputStream raw = new ByteArrayOutputStream();
      byte[] buf = new byte[8192];
      int n;
      while ((n = in.read(buf)) >= 0) {
        raw.write(buf, 0, n);
      }
      byte[] all = raw.toByteArray();
      int sep = indexOf(all, new byte[]{'\r', '\n', '\r', '\n'});
      if (sep < 0) {
        throw new IOException("Invalid HTTP/1.1 response");
      }
      String head = new String(all, 0, sep, StandardCharsets.ISO_8859_1);
      String[] lines = head.split("\r\n");
      String[] statusLine = lines[0].split(" ", 3);
      int status = Integer.parseInt(statusLine[1]);
      Map<String, List<String>> headers = new LinkedHashMap<>();
      for (int i = 1; i < lines.length; i++) {
        int c = lines[i].indexOf(':');
        if (c > 0) {
          String name = lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT);
          String value = lines[i].substring(c + 1).trim();
          headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
      }
      byte[] respBody = new byte[all.length - sep - 4];
      System.arraycopy(all, sep + 4, respBody, 0, respBody.length);
      String te = null;
      for (Map.Entry<String, List<String>> e : headers.entrySet()) {
        if (e.getKey().equalsIgnoreCase("transfer-encoding") && !e.getValue().isEmpty()) {
          te = e.getValue().get(0);
        }
      }
      if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
        respBody = decodeChunked(respBody);
      }
      return new HTTPClientResponse(status, headers, respBody, Protocols.HTTTP1_1);
    } finally {
      try {
        socket.close();
      } catch (IOException ignore) {
      }
    }
  }

  private Socket connect(boolean tls, String host, int port, boolean http2) throws IOException, GeneralSecurityException {
    Socket socket;
    if (tls) {
      SSLContext ctx;
      if (trustCertificates != null && trustCertificates.length > 0) {
        ctx = SecurityTools.clientContext(trustCertificates);
      } else {
        ctx = SSLContext.getDefault();
      }
      SSLSocketFactory factory = ctx.getSocketFactory();
      SSLSocket ssl = (SSLSocket) factory.createSocket();
      SSLParameters params = ssl.getSSLParameters();
      if (http2) {
        // Offer only h2 so servers that prefer http/1.1 still select HTTP/2 for this client.
        params.setApplicationProtocols(new String[]{"h2"});
      } else {
        params.setApplicationProtocols(new String[]{"http/1.1"});
      }
      try {
        params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
      } catch (IllegalArgumentException ignore) {
        // IP literals are not valid SNI host names
      }
      if (disableHostnameVerification) {
        params.setEndpointIdentificationAlgorithm(null);
      }
      ssl.setSSLParameters(params);
      ssl.connect(new InetSocketAddress(host, port), (int) connectTimeout.toMillis());
      ssl.startHandshake();
      if (http2 && version == Version.HTTP_2) {
        String ap = ssl.getApplicationProtocol();
        if (ap == null || ap.isEmpty()) {
          // Some stacks leave ALPN empty; HTTP/2 prior-knowledge preface still works on the TLS stream.
        } else if (!Protocols.H2.equals(ap)) {
          ssl.close();
          throw new IOException("Server did not negotiate HTTP/2 via ALPN (got: " + ap + ")");
        }
      }
      socket = ssl;
    } else {
      socket = new Socket();
      socket.connect(new InetSocketAddress(host, port), (int) connectTimeout.toMillis());
    }
    socket.setSoTimeout((int) readTimeout.toMillis());
    return socket;
  }

  private static String authority(String host, int port, boolean tls) {
    int def = tls ? 443 : 80;
    if (port == def) {
      return host;
    }
    return host + ":" + port;
  }

  private static int indexOf(byte[] data, byte[] pattern) {
    outer:
    for (int i = 0; i <= data.length - pattern.length; i++) {
      for (int j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private static byte[] decodeChunked(byte[] chunked) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int i = 0;
    while (i < chunked.length) {
      int lineEnd = indexOf(chunked, i, new byte[]{'\r', '\n'});
      if (lineEnd < 0) {
        break;
      }
      String sizeLine = new String(chunked, i, lineEnd - i, StandardCharsets.US_ASCII);
      int semi = sizeLine.indexOf(';');
      if (semi >= 0) {
        sizeLine = sizeLine.substring(0, semi);
      }
      int size = Integer.parseInt(sizeLine.trim(), 16);
      i = lineEnd + 2;
      if (size == 0) {
        break;
      }
      if (i + size > chunked.length) {
        throw new IOException("Truncated chunked body");
      }
      out.write(chunked, i, size);
      i += size;
      if (i + 1 < chunked.length && chunked[i] == '\r' && chunked[i + 1] == '\n') {
        i += 2;
      }
    }
    return out.toByteArray();
  }

  private static int indexOf(byte[] data, int from, byte[] pattern) {
    outer:
    for (int i = from; i <= data.length - pattern.length; i++) {
      for (int j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  @Override
  public void close() {
    // stateless client; nothing to close
  }
}
