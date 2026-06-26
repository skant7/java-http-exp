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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Reads and writes HTTP/2 frames on a byte stream.
 */
public final class HTTP2FrameIO {
  private HTTP2FrameIO() {
  }

  public static HTTP2Frame readFrame(InputStream in, int maxFrameSize) throws IOException {
    byte[] header = readFully(in, 9);
    int length = ((header[0] & 0xff) << 16) | ((header[1] & 0xff) << 8) | (header[2] & 0xff);
    if (length > maxFrameSize) {
      throw new HTTP2Exception(HTTP2ErrorCode.FRAME_SIZE_ERROR, "Frame length " + length + " exceeds max " + maxFrameSize);
    }
    int type = header[3] & 0xff;
    int flags = header[4] & 0xff;
    int streamId = ((header[5] & 0x7f) << 24) | ((header[6] & 0xff) << 16) | ((header[7] & 0xff) << 8) | (header[8] & 0xff);
    byte[] payload = length == 0 ? new byte[0] : readFully(in, length);
    return new HTTP2Frame(length, type, flags, streamId, payload);
  }

  public static void writeFrame(OutputStream out, int type, int flags, int streamId, byte[] payload) throws IOException {
    writeFrame(out, type, flags, streamId, payload, 0, payload == null ? 0 : payload.length);
  }

  public static void writeFrame(OutputStream out, int type, int flags, int streamId, byte[] payload, int offset, int length)
      throws IOException {
    if (length < 0 || length > 0x00ff_ffff) {
      throw new IllegalArgumentException("Invalid frame length: " + length);
    }
    byte[] header = new byte[9];
    header[0] = (byte) ((length >> 16) & 0xff);
    header[1] = (byte) ((length >> 8) & 0xff);
    header[2] = (byte) (length & 0xff);
    header[3] = (byte) type;
    header[4] = (byte) flags;
    header[5] = (byte) ((streamId >> 24) & 0x7f);
    header[6] = (byte) ((streamId >> 16) & 0xff);
    header[7] = (byte) ((streamId >> 8) & 0xff);
    header[8] = (byte) (streamId & 0xff);
    synchronized (out) {
      out.write(header);
      if (length > 0) {
        out.write(payload, offset, length);
      }
      out.flush();
    }
  }

  public static void writeSettings(OutputStream out, HTTP2Settings settings, boolean ack) throws IOException {
    if (ack) {
      writeFrame(out, HTTP2FrameType.SETTINGS, HTTP2Flags.ACK, 0, null);
      return;
    }
    // HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE
    byte[] payload = new byte[5 * 6];
    int i = 0;
    i = putSetting(payload, i, HTTP2Settings.HEADER_TABLE_SIZE, settings.getHeaderTableSize());
    i = putSetting(payload, i, HTTP2Settings.ENABLE_PUSH, settings.getEnablePush());
    i = putSetting(payload, i, HTTP2Settings.MAX_CONCURRENT_STREAMS, settings.getMaxConcurrentStreams() == Integer.MAX_VALUE ? 100 : settings.getMaxConcurrentStreams());
    i = putSetting(payload, i, HTTP2Settings.INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());
    putSetting(payload, i, HTTP2Settings.MAX_FRAME_SIZE, settings.getMaxFrameSize());
    writeFrame(out, HTTP2FrameType.SETTINGS, 0, 0, payload);
  }

  public static void writeGoAway(OutputStream out, int lastStreamId, HTTP2ErrorCode errorCode, byte[] debugData) throws IOException {
    int debugLen = debugData == null ? 0 : debugData.length;
    byte[] payload = new byte[8 + debugLen];
    payload[0] = (byte) ((lastStreamId >> 24) & 0x7f);
    payload[1] = (byte) ((lastStreamId >> 16) & 0xff);
    payload[2] = (byte) ((lastStreamId >> 8) & 0xff);
    payload[3] = (byte) (lastStreamId & 0xff);
    int code = errorCode.code;
    payload[4] = (byte) ((code >> 24) & 0xff);
    payload[5] = (byte) ((code >> 16) & 0xff);
    payload[6] = (byte) ((code >> 8) & 0xff);
    payload[7] = (byte) (code & 0xff);
    if (debugLen > 0) {
      System.arraycopy(debugData, 0, payload, 8, debugLen);
    }
    writeFrame(out, HTTP2FrameType.GOAWAY, 0, 0, payload);
  }

  public static void writeRstStream(OutputStream out, int streamId, HTTP2ErrorCode errorCode) throws IOException {
    byte[] payload = new byte[4];
    int code = errorCode.code;
    payload[0] = (byte) ((code >> 24) & 0xff);
    payload[1] = (byte) ((code >> 16) & 0xff);
    payload[2] = (byte) ((code >> 8) & 0xff);
    payload[3] = (byte) (code & 0xff);
    writeFrame(out, HTTP2FrameType.RST_STREAM, 0, streamId, payload);
  }

  public static void writeWindowUpdate(OutputStream out, int streamId, int increment) throws IOException {
    byte[] payload = new byte[4];
    payload[0] = (byte) ((increment >> 24) & 0x7f);
    payload[1] = (byte) ((increment >> 16) & 0xff);
    payload[2] = (byte) ((increment >> 8) & 0xff);
    payload[3] = (byte) (increment & 0xff);
    writeFrame(out, HTTP2FrameType.WINDOW_UPDATE, 0, streamId, payload);
  }

  public static void writePing(OutputStream out, byte[] opaque, boolean ack) throws IOException {
    if (opaque == null || opaque.length != 8) {
      throw new IllegalArgumentException("PING payload must be 8 bytes");
    }
    writeFrame(out, HTTP2FrameType.PING, ack ? HTTP2Flags.ACK : 0, 0, opaque);
  }

  private static int putSetting(byte[] payload, int offset, int id, int value) {
    payload[offset] = (byte) ((id >> 8) & 0xff);
    payload[offset + 1] = (byte) (id & 0xff);
    payload[offset + 2] = (byte) ((value >> 24) & 0xff);
    payload[offset + 3] = (byte) ((value >> 16) & 0xff);
    payload[offset + 4] = (byte) ((value >> 8) & 0xff);
    payload[offset + 5] = (byte) (value & 0xff);
    return offset + 6;
  }

  private static byte[] readFully(InputStream in, int length) throws IOException {
    byte[] buf = new byte[length];
    int off = 0;
    while (off < length) {
      int n = in.read(buf, off, length - off);
      if (n < 0) {
        throw new EOFException("Unexpected EOF reading HTTP/2 frame");
      }
      off += n;
    }
    return buf;
  }
}
