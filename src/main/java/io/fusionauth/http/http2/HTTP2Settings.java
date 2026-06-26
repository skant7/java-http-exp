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
 * HTTP/2 SETTINGS parameters (RFC 9113 §6.5.2).
 */
public class HTTP2Settings {
  public static final int HEADER_TABLE_SIZE = 0x1;
  public static final int ENABLE_PUSH = 0x2;
  public static final int MAX_CONCURRENT_STREAMS = 0x3;
  public static final int INITIAL_WINDOW_SIZE = 0x4;
  public static final int MAX_FRAME_SIZE = 0x5;
  public static final int MAX_HEADER_LIST_SIZE = 0x6;

  public static final int DEFAULT_HEADER_TABLE_SIZE = 4096;
  public static final int DEFAULT_ENABLE_PUSH = 1;
  public static final int DEFAULT_INITIAL_WINDOW_SIZE = 65_535;
  public static final int DEFAULT_MAX_FRAME_SIZE = 16_384;

  private int headerTableSize = DEFAULT_HEADER_TABLE_SIZE;
  private int enablePush = DEFAULT_ENABLE_PUSH;
  private int maxConcurrentStreams = Integer.MAX_VALUE;
  private int initialWindowSize = DEFAULT_INITIAL_WINDOW_SIZE;
  private int maxFrameSize = DEFAULT_MAX_FRAME_SIZE;
  private int maxHeaderListSize = Integer.MAX_VALUE;

  public HTTP2Settings copy() {
    HTTP2Settings copy = new HTTP2Settings();
    copy.headerTableSize = headerTableSize;
    copy.enablePush = enablePush;
    copy.maxConcurrentStreams = maxConcurrentStreams;
    copy.initialWindowSize = initialWindowSize;
    copy.maxFrameSize = maxFrameSize;
    copy.maxHeaderListSize = maxHeaderListSize;
    return copy;
  }

  public int getEnablePush() {
    return enablePush;
  }

  public int getHeaderTableSize() {
    return headerTableSize;
  }

  public int getInitialWindowSize() {
    return initialWindowSize;
  }

  public int getMaxConcurrentStreams() {
    return maxConcurrentStreams;
  }

  public int getMaxFrameSize() {
    return maxFrameSize;
  }

  public int getMaxHeaderListSize() {
    return maxHeaderListSize;
  }

  public void apply(int id, int value) {
    switch (id) {
      case HEADER_TABLE_SIZE -> headerTableSize = value;
      case ENABLE_PUSH -> enablePush = value;
      case MAX_CONCURRENT_STREAMS -> maxConcurrentStreams = value;
      case INITIAL_WINDOW_SIZE -> {
        if (value > 0x7fff_ffff) {
          throw new HTTP2Exception(HTTP2ErrorCode.FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE too large");
        }
        initialWindowSize = value;
      }
      case MAX_FRAME_SIZE -> {
        if (value < 16_384 || value > 16_777_215) {
          throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Invalid MAX_FRAME_SIZE");
        }
        maxFrameSize = value;
      }
      case MAX_HEADER_LIST_SIZE -> maxHeaderListSize = value;
      default -> {
        // ignore unknown settings
      }
    }
  }

  public void setEnablePush(int enablePush) {
    this.enablePush = enablePush;
  }

  public void setHeaderTableSize(int headerTableSize) {
    this.headerTableSize = headerTableSize;
  }

  public void setInitialWindowSize(int initialWindowSize) {
    this.initialWindowSize = initialWindowSize;
  }

  public void setMaxConcurrentStreams(int maxConcurrentStreams) {
    this.maxConcurrentStreams = maxConcurrentStreams;
  }

  public void setMaxFrameSize(int maxFrameSize) {
    this.maxFrameSize = maxFrameSize;
  }

  public void setMaxHeaderListSize(int maxHeaderListSize) {
    this.maxHeaderListSize = maxHeaderListSize;
  }
}
