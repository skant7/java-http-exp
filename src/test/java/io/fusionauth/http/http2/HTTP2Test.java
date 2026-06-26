/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
 */
package io.fusionauth.http.http2;

import java.nio.charset.StandardCharsets;

import io.fusionauth.http.BaseTest;
import io.fusionauth.http.HTTPValues.Protocols;
import io.fusionauth.http.client.HTTPClient;
import io.fusionauth.http.client.HTTPClientRequest;
import io.fusionauth.http.client.HTTPClientResponse;
import io.fusionauth.http.server.HTTPServer;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * HTTP/2 client and server integration tests (cleartext prior knowledge + TLS ALPN).
 */
public class HTTP2Test extends BaseTest {
  @Test
  public void h2cPriorKnowledgeGetAndPost() throws Exception {
    try (var ignore = makeServer("http", (req, res) -> {
      assertEquals(req.getProtocol(), Protocols.HTTTP2);
      assertEquals(req.getPath(), "/api/system/version");
      byte[] body = req.getInputStream().readAllBytes();
      res.setStatus(200);
      res.setHeader("content-type", "text/plain; charset=utf-8");
      String msg = "ok:" + req.getMethod() + ":" + new String(body, StandardCharsets.UTF_8);
      res.getOutputStream().write(msg.getBytes(StandardCharsets.UTF_8));
    }).start();
         HTTPClient client = new HTTPClient().withPriorKnowledgeH2c(true).withVersion(HTTPClient.Version.HTTP_2)) {

      HTTPClientResponse get = client.send(new HTTPClientRequest("http://localhost:4242/api/system/version"));
      assertEquals(get.getStatus(), 200);
      assertEquals(get.getProtocol(), Protocols.HTTTP2);
      assertEquals(get.getBodyAsString(), "ok:GET:");

      HTTPClientResponse post = client.send(new HTTPClientRequest("http://localhost:4242/api/system/version")
          .method("POST")
          .header("content-type", "text/plain")
          .body("payload"));
      assertEquals(post.getStatus(), 200);
      assertEquals(post.getProtocol(), Protocols.HTTTP2);
      assertEquals(post.getBodyAsString(), "ok:POST:payload");
    }
  }

  @Test
  public void h2TlsAlpnGet() throws Exception {
    try (var ignore = makeServer("https", (req, res) -> {
      assertEquals(req.getProtocol(), Protocols.HTTTP2);
      res.setStatus(200);
      res.getOutputStream().write("secure-h2".getBytes(StandardCharsets.UTF_8));
    }).start();
         HTTPClient client = new HTTPClient()
             .withVersion(HTTPClient.Version.HTTP_2)
             .withDisableHostnameVerification(true)
             .withTrustCertificates(certificate, intermediateCertificate, rootCertificate)) {

      HTTPClientResponse response = client.send(new HTTPClientRequest("https://local.fusionauth.io:4242/api/system/version"));
      assertEquals(response.getStatus(), 200);
      assertEquals(response.getProtocol(), Protocols.HTTTP2);
      assertEquals(response.getBodyAsString(), "secure-h2");
    }
  }

  @Test
  public void http11StillWorksAlongside() throws Exception {
    try (var ignore = makeServer("http", (req, res) -> {
      assertTrue(req.getProtocol().startsWith("HTTP/1"));
      res.setStatus(200);
      res.getOutputStream().write("http11".getBytes(StandardCharsets.UTF_8));
    }).start();
         HTTPClient client = new HTTPClient().withVersion(HTTPClient.Version.HTTP_1_1)) {

      HTTPClientResponse response = client.send(new HTTPClientRequest("http://localhost:4242/api/system/version"));
      assertEquals(response.getStatus(), 200);
      assertEquals(response.getProtocol(), Protocols.HTTTP1_1);
      assertEquals(response.getBodyAsString(), "http11");
    }
  }

  @Test
  public void hpackRoundTrip() {
    HPACKEncoder encoder = new HPACKEncoder(4096);
    HPACKDecoder decoder = new HPACKDecoder(4096);
    var headers = java.util.List.of(
        new HPACKHeader(":method", "GET"),
        new HPACKHeader(":path", "/"),
        new HPACKHeader(":scheme", "https"),
        new HPACKHeader(":authority", "example.com"),
        new HPACKHeader("accept", "text/plain")
    );
    byte[] block = encoder.encode(headers);
    var decoded = decoder.decode(block);
    assertEquals(decoded.size(), headers.size());
    for (int i = 0; i < headers.size(); i++) {
      assertEquals(decoded.get(i).name, headers.get(i).name);
      assertEquals(decoded.get(i).value, headers.get(i).value);
    }
  }
}
