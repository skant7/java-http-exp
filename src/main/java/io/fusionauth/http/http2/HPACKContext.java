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
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * HPACK dynamic table and integer/string helpers shared by encoder and decoder.
 */
public class HPACKContext {
  private final LinkedList<HPACKHeader> dynamic = new LinkedList<>();
  private int maxTableSize;
  private int currentSize;

  public HPACKContext(int maxTableSize) {
    this.maxTableSize = maxTableSize;
  }

  public void setMaxTableSize(int maxTableSize) {
    this.maxTableSize = maxTableSize;
    evict();
  }

  public int getMaxTableSize() {
    return maxTableSize;
  }

  public HPACKHeader get(int index) {
    if (index <= 0) {
      throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Invalid HPACK index " + index);
    }
    if (index <= HPACKStaticTable.LENGTH) {
      return new HPACKHeader(HPACKStaticTable.NAMES[index], HPACKStaticTable.VALUES[index]);
    }
    int dynIndex = index - HPACKStaticTable.LENGTH - 1;
    if (dynIndex >= dynamic.size()) {
      throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "HPACK index out of range: " + index);
    }
    return dynamic.get(dynIndex);
  }

  public int size() {
    return HPACKStaticTable.LENGTH + dynamic.size();
  }

  public void add(String name, String value) {
    int entrySize = 32 + name.length() + value.length();
    if (entrySize > maxTableSize) {
      dynamic.clear();
      currentSize = 0;
      return;
    }
    while (currentSize + entrySize > maxTableSize && !dynamic.isEmpty()) {
      evictOne();
    }
    dynamic.addFirst(new HPACKHeader(name, value));
    currentSize += entrySize;
  }

  public int findExact(String name, String value) {
    int staticExact = HPACKStaticTable.findExact(name, value);
    if (staticExact > 0) {
      return staticExact;
    }
    for (int i = 0; i < dynamic.size(); i++) {
      HPACKHeader h = dynamic.get(i);
      if (h.name.equals(name) && h.value.equals(value)) {
        return HPACKStaticTable.LENGTH + 1 + i;
      }
    }
    return -1;
  }

  public int findName(String name) {
    int staticName = HPACKStaticTable.findName(name);
    if (staticName > 0) {
      return staticName;
    }
    for (int i = 0; i < dynamic.size(); i++) {
      if (dynamic.get(i).name.equals(name)) {
        return HPACKStaticTable.LENGTH + 1 + i;
      }
    }
    return -1;
  }

  private void evict() {
    while (currentSize > maxTableSize && !dynamic.isEmpty()) {
      evictOne();
    }
  }

  private void evictOne() {
    HPACKHeader removed = dynamic.removeLast();
    currentSize -= 32 + removed.name.length() + removed.value.length();
    if (currentSize < 0) {
      currentSize = 0;
    }
  }

  public static int decodeInteger(byte[] data, int offset, int prefixBits, int[] consumed) {
    int mask = (1 << prefixBits) - 1;
    int value = data[offset] & mask;
    int i = 1;
    if (value < mask) {
      consumed[0] = i;
      return value;
    }
    int m = 0;
    int b;
    do {
      if (offset + i >= data.length) {
        throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Truncated HPACK integer");
      }
      b = data[offset + i] & 0xff;
      i++;
      value += (b & 0x7f) << m;
      m += 7;
    } while ((b & 0x80) != 0);
    consumed[0] = i;
    return value;
  }

  public static int encodeInteger(byte[] out, int offset, int value, int prefixBits, int prefixHighBits) {
    int mask = (1 << prefixBits) - 1;
    if (value < mask) {
      out[offset] = (byte) (prefixHighBits | value);
      return 1;
    }
    out[offset] = (byte) (prefixHighBits | mask);
    value -= mask;
    int i = 1;
    while (value >= 128) {
      out[offset + i] = (byte) ((value & 0x7f) | 0x80);
      value >>>= 7;
      i++;
    }
    out[offset + i] = (byte) value;
    return i + 1;
  }

  public static String decodeString(byte[] data, int offset, int[] consumed) {
    boolean huffman = (data[offset] & 0x80) != 0;
    int[] c = new int[1];
    int length = decodeInteger(data, offset, 7, c);
    int start = offset + c[0];
    if (start + length > data.length) {
      throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Truncated HPACK string");
    }
    byte[] raw = new byte[length];
    System.arraycopy(data, start, raw, 0, length);
    consumed[0] = c[0] + length;
    if (huffman) {
      return HPACKHuffman.decodeString(raw);
    }
    return new String(raw, StandardCharsets.ISO_8859_1);
  }

  public static byte[] encodeString(String value, boolean preferHuffman) {
    byte[] raw = value.getBytes(StandardCharsets.ISO_8859_1);
    byte[] encoded = preferHuffman ? HPACKHuffman.encode(raw) : raw;
    boolean useHuffman = preferHuffman && encoded.length < raw.length;
    if (!useHuffman) {
      encoded = raw;
    }
    byte[] lengthBuf = new byte[11];
    int lenBytes = encodeInteger(lengthBuf, 0, encoded.length, 7, useHuffman ? 0x80 : 0x00);
    byte[] out = new byte[lenBytes + encoded.length];
    System.arraycopy(lengthBuf, 0, out, 0, lenBytes);
    System.arraycopy(encoded, 0, out, lenBytes, encoded.length);
    return out;
  }
}
