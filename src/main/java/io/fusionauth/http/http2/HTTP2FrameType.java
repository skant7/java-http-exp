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
 * HTTP/2 frame types from RFC 9113 §6.
 */
public final class HTTP2FrameType {
  public static final int DATA = 0x0;
  public static final int HEADERS = 0x1;
  public static final int PRIORITY = 0x2;
  public static final int RST_STREAM = 0x3;
  public static final int SETTINGS = 0x4;
  public static final int PUSH_PROMISE = 0x5;
  public static final int PING = 0x6;
  public static final int GOAWAY = 0x7;
  public static final int WINDOW_UPDATE = 0x8;
  public static final int CONTINUATION = 0x9;

  private HTTP2FrameType() {
  }
}
