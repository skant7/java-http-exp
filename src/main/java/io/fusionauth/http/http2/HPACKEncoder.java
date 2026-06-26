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
import java.io.IOException;
import java.util.List;

/**
 * HPACK encoder (RFC 7541). Uses indexed representation when possible, otherwise
 * literal with incremental indexing.
 */
public class HPACKEncoder {
  private final HPACKContext context;
  private final boolean preferHuffman;

  public HPACKEncoder(int maxTableSize) {
    this(maxTableSize, true);
  }

  public HPACKEncoder(int maxTableSize, boolean preferHuffman) {
    this.context = new HPACKContext(maxTableSize);
    this.preferHuffman = preferHuffman;
  }

  public HPACKContext context() {
    return context;
  }

  public byte[] encode(List<HPACKHeader> headers) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(256);
    try {
      for (HPACKHeader header : headers) {
        String name = header.name.toLowerCase();
        String value = header.value;
        int exact = context.findExact(name, value);
        if (exact > 0) {
          writeIndexed(out, exact);
          continue;
        }
        int nameIndex = context.findName(name);
        writeLiteralIncremental(out, nameIndex, name, value);
        context.add(name, value);
      }
    } catch (IOException e) {
      throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, e.getMessage());
    }
    return out.toByteArray();
  }

  private void writeIndexed(ByteArrayOutputStream out, int index) throws IOException {
    byte[] buf = new byte[11];
    int n = HPACKContext.encodeInteger(buf, 0, index, 7, 0x80);
    out.write(buf, 0, n);
  }

  private void writeLiteralIncremental(ByteArrayOutputStream out, int nameIndex, String name, String value)
      throws IOException {
    byte[] buf = new byte[11];
    if (nameIndex > 0) {
      int n = HPACKContext.encodeInteger(buf, 0, nameIndex, 6, 0x40);
      out.write(buf, 0, n);
    } else {
      out.write(0x40);
      out.write(HPACKContext.encodeString(name, preferHuffman));
    }
    out.write(HPACKContext.encodeString(value, preferHuffman));
  }
}
