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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Multiplexed HTTP/2 connection (client or server side). Manages framing, HPACK,
 * settings, flow control windows, and stream lifecycle for basic request/response.
 */
public class HTTP2Connection implements AutoCloseable {
  private final InputStream in;
  private final OutputStream out;
  private final boolean server;
  private final HTTP2Settings localSettings;
  private final HTTP2Settings remoteSettings = new HTTP2Settings();
  private final HPACKDecoder decoder;
  private final HPACKEncoder encoder;
  private final Map<Integer, HTTP2Stream> streams = new ConcurrentHashMap<>();
  private final AtomicInteger nextClientStreamId = new AtomicInteger(1);
  private final AtomicInteger connectionSendWindow = new AtomicInteger(HTTP2Settings.DEFAULT_INITIAL_WINDOW_SIZE);
  private final AtomicInteger connectionRecvWindow = new AtomicInteger(HTTP2Settings.DEFAULT_INITIAL_WINDOW_SIZE);
  private volatile boolean closed;
  private volatile int lastStreamId;
  private Consumer<HTTP2Stream> onHeadersComplete;

  public HTTP2Connection(InputStream in, OutputStream out, boolean server, HTTP2Settings localSettings) {
    this.in = in;
    this.out = out;
    this.server = server;
    this.localSettings = localSettings == null ? new HTTP2Settings() : localSettings;
    if (server) {
      this.localSettings.setEnablePush(0);
    }
    this.decoder = new HPACKDecoder(this.localSettings.getHeaderTableSize());
    this.encoder = new HPACKEncoder(this.remoteSettings.getHeaderTableSize());
  }

  public void setOnHeadersComplete(Consumer<HTTP2Stream> onHeadersComplete) {
    this.onHeadersComplete = onHeadersComplete;
  }

  public HTTP2Settings getLocalSettings() {
    return localSettings;
  }

  public HTTP2Settings getRemoteSettings() {
    return remoteSettings;
  }

  /**
   * Client: write connection preface then SETTINGS. Server: expect preface already consumed.
   */
  public void handshake() throws IOException {
    if (!server) {
      out.write(HTTP2Preface.CLIENT_PREFACE);
      out.flush();
    }
    HTTP2FrameIO.writeSettings(out, localSettings, false);
  }

  public HTTP2Stream getStream(int id) {
    return streams.get(id);
  }

  public HTTP2Stream openClientStream() {
    if (server) {
      throw new IllegalStateException("Server cannot open client streams");
    }
    int id = nextClientStreamId.getAndAdd(2);
    HTTP2Stream stream = new HTTP2Stream(id, remoteSettings.getInitialWindowSize());
    stream.setState(HTTP2StreamState.IDLE);
    streams.put(id, stream);
    lastStreamId = Math.max(lastStreamId, id);
    return stream;
  }

  public void sendHeaders(HTTP2Stream stream, List<HPACKHeader> headers, boolean endStream) throws IOException {
    byte[] block = encoder.encode(headers);
    int maxFrame = remoteSettings.getMaxFrameSize();
    int offset = 0;
    boolean first = true;
    while (offset < block.length || first) {
      first = false;
      int chunk = Math.min(maxFrame, block.length - offset);
      boolean lastHeaders = offset + chunk >= block.length;
      int flags = 0;
      if (lastHeaders) {
        flags |= HTTP2Flags.END_HEADERS;
      }
      if (endStream && lastHeaders) {
        flags |= HTTP2Flags.END_STREAM;
      }
      int type = offset == 0 ? HTTP2FrameType.HEADERS : HTTP2FrameType.CONTINUATION;
      // CONTINUATION cannot have END_STREAM; END_STREAM only on HEADERS/DATA
      if (type == HTTP2FrameType.CONTINUATION) {
        flags &= ~HTTP2Flags.END_STREAM;
      }
      byte[] payload = new byte[chunk];
      if (chunk > 0) {
        System.arraycopy(block, offset, payload, 0, chunk);
      }
      HTTP2FrameIO.writeFrame(out, type, flags, stream.id, payload);
      offset += chunk;
      if (chunk == 0) {
        break;
      }
    }
    if (stream.getState() == HTTP2StreamState.IDLE) {
      stream.setState(endStream ? HTTP2StreamState.HALF_CLOSED_LOCAL : HTTP2StreamState.OPEN);
    } else if (endStream) {
      if (stream.getState() == HTTP2StreamState.OPEN) {
        stream.setState(HTTP2StreamState.HALF_CLOSED_LOCAL);
      } else if (stream.getState() == HTTP2StreamState.HALF_CLOSED_REMOTE) {
        stream.setState(HTTP2StreamState.CLOSED);
      }
    }
  }

  public void sendData(HTTP2Stream stream, byte[] data, boolean endStream) throws IOException {
    if (data == null) {
      data = new byte[0];
    }
    int maxFrame = remoteSettings.getMaxFrameSize();
    int offset = 0;
    if (data.length == 0 && endStream) {
      HTTP2FrameIO.writeFrame(out, HTTP2FrameType.DATA, HTTP2Flags.END_STREAM, stream.id, new byte[0]);
      return;
    }
    while (offset < data.length) {
      int chunk = Math.min(maxFrame, data.length - offset);
      // Simple flow control: wait is not implemented; assume adequate windows for tests
      boolean last = offset + chunk >= data.length;
      int flags = (last && endStream) ? HTTP2Flags.END_STREAM : 0;
      HTTP2FrameIO.writeFrame(out, HTTP2FrameType.DATA, flags, stream.id, data, offset, chunk);
      stream.consumeSendWindow(chunk);
      connectionSendWindow.addAndGet(-chunk);
      offset += chunk;
    }
  }

  /**
   * Read and process frames until {@code stop} returns true or the connection is closed.
   */
  public void readLoop(java.util.function.BooleanSupplier stop) throws IOException {
    while (!closed && (stop == null || !stop.getAsBoolean())) {
      HTTP2Frame frame = HTTP2FrameIO.readFrame(in, localSettings.getMaxFrameSize());
      handleFrame(frame);
    }
  }

  /**
   * Read a single frame and process it. Returns false on GOAWAY / close.
   */
  public boolean processOneFrame() throws IOException {
    if (closed) {
      return false;
    }
    HTTP2Frame frame = HTTP2FrameIO.readFrame(in, localSettings.getMaxFrameSize());
    return handleFrame(frame);
  }

  private boolean handleFrame(HTTP2Frame frame) throws IOException {
    switch (frame.type) {
      case HTTP2FrameType.DATA -> handleData(frame);
      case HTTP2FrameType.HEADERS, HTTP2FrameType.CONTINUATION -> handleHeaders(frame);
      case HTTP2FrameType.SETTINGS -> handleSettings(frame);
      case HTTP2FrameType.PING -> handlePing(frame);
      case HTTP2FrameType.GOAWAY -> {
        closed = true;
        return false;
      }
      case HTTP2FrameType.WINDOW_UPDATE -> handleWindowUpdate(frame);
      case HTTP2FrameType.RST_STREAM -> handleRst(frame);
      case HTTP2FrameType.PRIORITY, HTTP2FrameType.PUSH_PROMISE -> {
        // ignore / not implemented
      }
      default -> {
        // ignore unknown
      }
    }
    return true;
  }

  private void handleData(HTTP2Frame frame) throws IOException {
    if (frame.streamId == 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "DATA on stream 0");
    }
    HTTP2Stream stream = streams.get(frame.streamId);
    if (stream == null) {
      HTTP2FrameIO.writeRstStream(out, frame.streamId, HTTP2ErrorCode.STREAM_CLOSED);
      return;
    }
    byte[] payload = frame.payload;
    int pad = 0;
    if (HTTP2Flags.isSet(frame.flags, HTTP2Flags.PADDED)) {
      pad = payload[0] & 0xff;
      if (1 + pad > payload.length) {
        throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Invalid DATA padding");
      }
      byte[] data = new byte[payload.length - 1 - pad];
      System.arraycopy(payload, 1, data, 0, data.length);
      payload = data;
    }
    stream.appendData(payload, HTTP2Flags.isSet(frame.flags, HTTP2Flags.END_STREAM));
    stream.consumeRecvWindow(payload.length);
    connectionRecvWindow.addAndGet(-payload.length);
    // replenish windows proactively
    if (stream.getRecvWindow() < localSettings.getInitialWindowSize() / 2) {
      int credit = localSettings.getInitialWindowSize() - stream.getRecvWindow();
      stream.creditRecvWindow(credit);
      HTTP2FrameIO.writeWindowUpdate(out, stream.id, credit);
    }
    if (connectionRecvWindow.get() < localSettings.getInitialWindowSize() / 2) {
      int credit = localSettings.getInitialWindowSize() - connectionRecvWindow.get();
      connectionRecvWindow.addAndGet(credit);
      HTTP2FrameIO.writeWindowUpdate(out, 0, credit);
    }
  }

  private void handleHeaders(HTTP2Frame frame) throws IOException {
    if (frame.streamId == 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "HEADERS on stream 0");
    }
    HTTP2Stream stream = streams.computeIfAbsent(frame.streamId, id -> {
      HTTP2Stream s = new HTTP2Stream(id, remoteSettings.getInitialWindowSize());
      s.setState(HTTP2StreamState.OPEN);
      return s;
    });
    lastStreamId = Math.max(lastStreamId, frame.streamId);

    byte[] payload = frame.payload;
    int offset = 0;
    if (frame.type == HTTP2FrameType.HEADERS && HTTP2Flags.isSet(frame.flags, HTTP2Flags.PADDED)) {
      int pad = payload[0] & 0xff;
      offset = 1;
      if (offset + pad > payload.length) {
        throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Invalid HEADERS padding");
      }
      // trim padding from end conceptually by reducing effective length
      payload = trimPad(payload, offset, pad);
      offset = 0;
    }
    if (frame.type == HTTP2FrameType.HEADERS && HTTP2Flags.isSet(frame.flags, HTTP2Flags.PRIORITY)) {
      offset += 5; // dependency + weight
      if (offset > payload.length) {
        throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Invalid HEADERS priority");
      }
    }
    byte[] block = new byte[payload.length - offset];
    System.arraycopy(payload, offset, block, 0, block.length);
    boolean endHeaders = HTTP2Flags.isSet(frame.flags, HTTP2Flags.END_HEADERS);
    boolean endStream = HTTP2Flags.isSet(frame.flags, HTTP2Flags.END_STREAM);
    stream.appendHeaderBlock(block, endHeaders);
    if (endStream) {
      stream.markEndStreamReceived();
      if (stream.getState() == HTTP2StreamState.OPEN) {
        stream.setState(HTTP2StreamState.HALF_CLOSED_REMOTE);
      }
    }
    if (endHeaders) {
      List<HPACKHeader> headers = decoder.decode(stream.getHeaderBlock());
      stream.setHeaders(headers);
      if (onHeadersComplete != null) {
        onHeadersComplete.accept(stream);
      }
    }
  }

  private static byte[] trimPad(byte[] payload, int offset, int pad) {
    int len = payload.length - offset - pad;
    byte[] out = new byte[len];
    System.arraycopy(payload, offset, out, 0, len);
    return out;
  }

  private void handleSettings(HTTP2Frame frame) throws IOException {
    if (frame.streamId != 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "SETTINGS on non-zero stream");
    }
    if (HTTP2Flags.isSet(frame.flags, HTTP2Flags.ACK)) {
      return;
    }
    if (frame.payload.length % 6 != 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.FRAME_SIZE_ERROR, "Invalid SETTINGS payload");
    }
    for (int i = 0; i < frame.payload.length; i += 6) {
      int id = ((frame.payload[i] & 0xff) << 8) | (frame.payload[i + 1] & 0xff);
      int value = ((frame.payload[i + 2] & 0xff) << 24) | ((frame.payload[i + 3] & 0xff) << 16)
          | ((frame.payload[i + 4] & 0xff) << 8) | (frame.payload[i + 5] & 0xff);
      remoteSettings.apply(id, value);
      if (id == HTTP2Settings.HEADER_TABLE_SIZE) {
        encoder.context().setMaxTableSize(value);
      }
      if (id == HTTP2Settings.INITIAL_WINDOW_SIZE) {
        // simplistic: not adjusting existing stream windows delta
      }
    }
    HTTP2FrameIO.writeSettings(out, localSettings, true);
  }

  private void handlePing(HTTP2Frame frame) throws IOException {
    if (frame.streamId != 0 || frame.payload.length != 8) {
      throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Invalid PING");
    }
    if (!HTTP2Flags.isSet(frame.flags, HTTP2Flags.ACK)) {
      HTTP2FrameIO.writePing(out, frame.payload, true);
    }
  }

  private void handleWindowUpdate(HTTP2Frame frame) {
    if (frame.payload.length != 4) {
      throw new HTTP2Exception(HTTP2ErrorCode.FRAME_SIZE_ERROR, "WINDOW_UPDATE length");
    }
    int inc = ((frame.payload[0] & 0x7f) << 24) | ((frame.payload[1] & 0xff) << 16)
        | ((frame.payload[2] & 0xff) << 8) | (frame.payload[3] & 0xff);
    if (inc == 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.PROTOCOL_ERROR, "Zero WINDOW_UPDATE");
    }
    if (frame.streamId == 0) {
      connectionSendWindow.addAndGet(inc);
    } else {
      HTTP2Stream stream = streams.get(frame.streamId);
      if (stream != null) {
        stream.creditSendWindow(inc);
      }
    }
  }

  private void handleRst(HTTP2Frame frame) {
    HTTP2Stream stream = streams.get(frame.streamId);
    if (stream != null) {
      stream.setState(HTTP2StreamState.CLOSED);
    }
  }

  public void goAway(HTTP2ErrorCode code, String debug) throws IOException {
    byte[] data = debug == null ? null : debug.getBytes();
    HTTP2FrameIO.writeGoAway(out, lastStreamId, code, data);
    closed = true;
  }

  public boolean isClosed() {
    return closed;
  }

  public OutputStream getOutputStream() {
    return out;
  }

  @Override
  public void close() {
    closed = true;
    try {
      in.close();
    } catch (IOException ignore) {
    }
    try {
      out.close();
    } catch (IOException ignore) {
    }
  }
}
