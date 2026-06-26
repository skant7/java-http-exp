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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Response returned by {@link HTTPClient}.
 */
public class HTTPClientResponse {
  private final int status;
  private final Map<String, List<String>> headers;
  private final byte[] body;
  private final String protocol;

  public HTTPClientResponse(int status, Map<String, List<String>> headers, byte[] body, String protocol) {
    this.status = status;
    this.headers = headers == null ? Map.of() : Collections.unmodifiableMap(headers);
    this.body = body == null ? new byte[0] : body;
    this.protocol = protocol;
  }

  public int getStatus() {
    return status;
  }

  public Map<String, List<String>> getHeaders() {
    return headers;
  }

  public String getHeader(String name) {
    List<String> values = headers.get(name.toLowerCase());
    if (values == null && headers.containsKey(name)) {
      values = headers.get(name);
    }
    // headers stored lower-case from parsers
    for (Map.Entry<String, List<String>> e : headers.entrySet()) {
      if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
        return e.getValue().get(0);
      }
    }
    return null;
  }

  public byte[] getBody() {
    return body;
  }

  public String getBodyAsString() {
    return getBodyAsString(StandardCharsets.UTF_8);
  }

  public String getBodyAsString(Charset charset) {
    return new String(body, charset);
  }

  public String getProtocol() {
    return protocol;
  }
}
