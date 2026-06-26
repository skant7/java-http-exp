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

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An HTTP/2 stream with buffered headers and body.
 */
public class HTTP2Stream {
  public final int id;
  private final AtomicInteger sendWindow;
  private final AtomicInteger recvWindow;
  private final ByteArrayOutputStream data = new ByteArrayOutputStream();
  private final ByteArrayOutputStream headerBlock = new ByteArrayOutputStream();
  private final CountDownLatch headersComplete = new CountDownLatch(1);
  private final CountDownLatch endStream = new CountDownLatch(1);
  private volatile HTTP2StreamState state = HTTP2StreamState.IDLE;
  private volatile List<HPACKHeader> headers = List.of();
  private volatile boolean endStreamReceived;
  private volatile boolean headersReceived;

  public HTTP2Stream(int id, int initialWindow) {
    this.id = id;
    this.sendWindow = new AtomicInteger(initialWindow);
    this.recvWindow = new AtomicInteger(initialWindow);
  }

  public synchronized void appendHeaderBlock(byte[] block, boolean endHeaders) {
    headerBlock.writeBytes(block);
    if (endHeaders) {
      headersReceived = true;
      headersComplete.countDown();
    }
  }

  public synchronized void appendData(byte[] payload, boolean endStreamFlag) {
    data.writeBytes(payload);
    if (endStreamFlag) {
      endStreamReceived = true;
      endStream.countDown();
      if (state == HTTP2StreamState.OPEN) {
        state = HTTP2StreamState.HALF_CLOSED_REMOTE;
      } else if (state == HTTP2StreamState.HALF_CLOSED_LOCAL) {
        state = HTTP2StreamState.CLOSED;
      }
    }
  }

  public void setHeaders(List<HPACKHeader> headers) {
    this.headers = new ArrayList<>(headers);
  }

  public List<HPACKHeader> getHeaders() {
    return headers;
  }

  public byte[] getHeaderBlock() {
    return headerBlock.toByteArray();
  }

  public byte[] getData() {
    return data.toByteArray();
  }

  public HTTP2StreamState getState() {
    return state;
  }

  public void setState(HTTP2StreamState state) {
    this.state = state;
  }

  public boolean isEndStreamReceived() {
    return endStreamReceived;
  }

  public boolean isHeadersReceived() {
    return headersReceived;
  }

  public boolean awaitHeaders(long timeout, TimeUnit unit) throws InterruptedException {
    return headersComplete.await(timeout, unit);
  }

  public boolean awaitEndStream(long timeout, TimeUnit unit) throws InterruptedException {
    return endStream.await(timeout, unit);
  }

  public void markEndStreamReceived() {
    endStreamReceived = true;
    endStream.countDown();
  }

  public int getSendWindow() {
    return sendWindow.get();
  }

  public int getRecvWindow() {
    return recvWindow.get();
  }

  public void consumeSendWindow(int n) {
    sendWindow.addAndGet(-n);
  }

  public void creditSendWindow(int n) {
    sendWindow.addAndGet(n);
  }

  public void consumeRecvWindow(int n) {
    recvWindow.addAndGet(-n);
  }

  public void creditRecvWindow(int n) {
    recvWindow.addAndGet(n);
  }
}
