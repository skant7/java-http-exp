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

import java.util.ArrayList;
import java.util.List;

/**
 * HPACK decoder (RFC 7541).
 */
public class HPACKDecoder {
  private final HPACKContext context;

  public HPACKDecoder(int maxTableSize) {
    this.context = new HPACKContext(maxTableSize);
  }

  public HPACKContext context() {
    return context;
  }

  public List<HPACKHeader> decode(byte[] block) {
    List<HPACKHeader> headers = new ArrayList<>();
    int offset = 0;
    int[] consumed = new int[1];
    while (offset < block.length) {
      int b = block[offset] & 0xff;
      if ((b & 0x80) != 0) {
        // Indexed Header Field
        int index = HPACKContext.decodeInteger(block, offset, 7, consumed);
        offset += consumed[0];
        if (index == 0) {
          throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Invalid indexed header 0");
        }
        headers.add(context.get(index));
      } else if ((b & 0xc0) == 0x40) {
        // Literal with incremental indexing
        int index = HPACKContext.decodeInteger(block, offset, 6, consumed);
        offset += consumed[0];
        String name;
        String value;
        if (index == 0) {
          name = HPACKContext.decodeString(block, offset, consumed).toLowerCase();
          offset += consumed[0];
        } else {
          name = context.get(index).name;
        }
        value = HPACKContext.decodeString(block, offset, consumed);
        offset += consumed[0];
        context.add(name, value);
        headers.add(new HPACKHeader(name, value));
      } else if ((b & 0xe0) == 0x20) {
        // Dynamic table size update
        int size = HPACKContext.decodeInteger(block, offset, 5, consumed);
        offset += consumed[0];
        context.setMaxTableSize(size);
      } else {
        // Literal without indexing (0x00) or never indexed (0x10)
        int prefix = ((b & 0xf0) == 0x10) ? 4 : 4;
        int index = HPACKContext.decodeInteger(block, offset, prefix, consumed);
        offset += consumed[0];
        String name;
        if (index == 0) {
          name = HPACKContext.decodeString(block, offset, consumed).toLowerCase();
          offset += consumed[0];
        } else {
          name = context.get(index).name;
        }
        String value = HPACKContext.decodeString(block, offset, consumed);
        offset += consumed[0];
        headers.add(new HPACKHeader(name, value));
      }
    }
    return headers;
  }
}
