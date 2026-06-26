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

/**
 * HTTP/2 error codes from RFC 9113 §7.
 */
public enum HTTP2ErrorCode {
  NO_ERROR(0x0),
  PROTOCOL_ERROR(0x1),
  INTERNAL_ERROR(0x2),
  FLOW_CONTROL_ERROR(0x3),
  SETTINGS_TIMEOUT(0x4),
  STREAM_CLOSED(0x5),
  FRAME_SIZE_ERROR(0x6),
  REFUSED_STREAM(0x7),
  CANCEL(0x8),
  COMPRESSION_ERROR(0x9),
  CONNECT_ERROR(0xa),
  ENHANCE_YOUR_CALM(0xb),
  INADEQUATE_SECURITY(0xc),
  HTTP_1_1_REQUIRED(0xd);

  public final int code;

  HTTP2ErrorCode(int code) {
    this.code = code;
  }

  public static HTTP2ErrorCode fromCode(int code) {
    for (HTTP2ErrorCode e : values()) {
      if (e.code == code) {
        return e;
      }
    }
    return INTERNAL_ERROR;
  }
}
