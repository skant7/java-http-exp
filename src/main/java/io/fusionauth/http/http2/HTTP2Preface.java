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
package io.fusionauth.http.http2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HTTP/2 connection preface (RFC 9113 §3.4).
 */
public final class HTTP2Preface {
  public static final byte[] CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

  private HTTP2Preface() {
  }

  public static boolean matches(byte[] bytes, int offset, int length) {
    if (length < CLIENT_PREFACE.length) {
      return false;
    }
    return Arrays.equals(CLIENT_PREFACE, 0, CLIENT_PREFACE.length, bytes, offset, offset + CLIENT_PREFACE.length);
  }
}
