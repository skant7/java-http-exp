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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A simple outbound HTTP request for {@link HTTPClient}.
 */
public class HTTPClientRequest {
  private final URI uri;
  private String method = "GET";
  private final Map<String, List<String>> headers = new LinkedHashMap<>();
  private byte[] body;

  public HTTPClientRequest(URI uri) {
    this.uri = uri;
  }

  public HTTPClientRequest(String uri) {
    this(URI.create(uri));
  }

  public URI getUri() {
    return uri;
  }

  public String getMethod() {
    return method;
  }

  public HTTPClientRequest method(String method) {
    this.method = method;
    return this;
  }

  public Map<String, List<String>> getHeaders() {
    return headers;
  }

  public HTTPClientRequest header(String name, String value) {
    headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    return this;
  }

  public byte[] getBody() {
    return body;
  }

  public HTTPClientRequest body(byte[] body) {
    this.body = body;
    return this;
  }

  public HTTPClientRequest body(String body) {
    this.body = body.getBytes(StandardCharsets.UTF_8);
    return this;
  }
}
