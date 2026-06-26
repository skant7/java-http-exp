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
 * Exception carrying an HTTP/2 error code for GOAWAY / RST_STREAM.
 */
public class HTTP2Exception extends RuntimeException {
  public final HTTP2ErrorCode errorCode;
  public final int streamId;

  public HTTP2Exception(HTTP2ErrorCode errorCode, String message) {
    this(errorCode, 0, message);
  }

  public HTTP2Exception(HTTP2ErrorCode errorCode, int streamId, String message) {
    super(message);
    this.errorCode = errorCode;
    this.streamId = streamId;
  }
}
