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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HPACK Huffman coding (RFC 7541 Appendix B).
 */
public final class HPACKHuffman {
  private static final int[] CODES = new int[257];
  private static final byte[] BITS = new byte[257];
  private static final Node ROOT = new Node();

  static {
    CODES[0] = 0x1ff8;
    BITS[0] = 13;
    CODES[1] = 0x7fffd8;
    BITS[1] = 23;
    CODES[2] = 0xfffffe2;
    BITS[2] = 28;
    CODES[3] = 0xfffffe3;
    BITS[3] = 28;
    CODES[4] = 0xfffffe4;
    BITS[4] = 28;
    CODES[5] = 0xfffffe5;
    BITS[5] = 28;
    CODES[6] = 0xfffffe6;
    BITS[6] = 28;
    CODES[7] = 0xfffffe7;
    BITS[7] = 28;
    CODES[8] = 0xfffffe8;
    BITS[8] = 28;
    CODES[9] = 0xffffea;
    BITS[9] = 24;
    CODES[10] = 0x3ffffffc;
    BITS[10] = 30;
    CODES[11] = 0xfffffe9;
    BITS[11] = 28;
    CODES[12] = 0xfffffea;
    BITS[12] = 28;
    CODES[13] = 0x3ffffffd;
    BITS[13] = 30;
    CODES[14] = 0xfffffeb;
    BITS[14] = 28;
    CODES[15] = 0xfffffec;
    BITS[15] = 28;
    CODES[16] = 0xfffffed;
    BITS[16] = 28;
    CODES[17] = 0xfffffee;
    BITS[17] = 28;
    CODES[18] = 0xfffffef;
    BITS[18] = 28;
    CODES[19] = 0xffffff0;
    BITS[19] = 28;
    CODES[20] = 0xffffff1;
    BITS[20] = 28;
    CODES[21] = 0xffffff2;
    BITS[21] = 28;
    CODES[22] = 0x3ffffffe;
    BITS[22] = 30;
    CODES[23] = 0xffffff3;
    BITS[23] = 28;
    CODES[24] = 0xffffff4;
    BITS[24] = 28;
    CODES[25] = 0xffffff5;
    BITS[25] = 28;
    CODES[26] = 0xffffff6;
    BITS[26] = 28;
    CODES[27] = 0xffffff7;
    BITS[27] = 28;
    CODES[28] = 0xffffff8;
    BITS[28] = 28;
    CODES[29] = 0xffffff9;
    BITS[29] = 28;
    CODES[30] = 0xffffffa;
    BITS[30] = 28;
    CODES[31] = 0xffffffb;
    BITS[31] = 28;
    CODES[32] = 0x14;
    BITS[32] = 6;
    CODES[33] = 0x3f8;
    BITS[33] = 10;
    CODES[34] = 0x3f9;
    BITS[34] = 10;
    CODES[35] = 0xffa;
    BITS[35] = 12;
    CODES[36] = 0x1ff9;
    BITS[36] = 13;
    CODES[37] = 0x15;
    BITS[37] = 6;
    CODES[38] = 0xf8;
    BITS[38] = 8;
    CODES[39] = 0x7fa;
    BITS[39] = 11;
    CODES[40] = 0x3fa;
    BITS[40] = 10;
    CODES[41] = 0x3fb;
    BITS[41] = 10;
    CODES[42] = 0xf9;
    BITS[42] = 8;
    CODES[43] = 0x7fb;
    BITS[43] = 11;
    CODES[44] = 0xfa;
    BITS[44] = 8;
    CODES[45] = 0x16;
    BITS[45] = 6;
    CODES[46] = 0x17;
    BITS[46] = 6;
    CODES[47] = 0x18;
    BITS[47] = 6;
    CODES[48] = 0x0;
    BITS[48] = 5;
    CODES[49] = 0x1;
    BITS[49] = 5;
    CODES[50] = 0x2;
    BITS[50] = 5;
    CODES[51] = 0x19;
    BITS[51] = 6;
    CODES[52] = 0x1a;
    BITS[52] = 6;
    CODES[53] = 0x1b;
    BITS[53] = 6;
    CODES[54] = 0x1c;
    BITS[54] = 6;
    CODES[55] = 0x1d;
    BITS[55] = 6;
    CODES[56] = 0x1e;
    BITS[56] = 6;
    CODES[57] = 0x1f;
    BITS[57] = 6;
    CODES[58] = 0x5c;
    BITS[58] = 7;
    CODES[59] = 0xfb;
    BITS[59] = 8;
    CODES[60] = 0x7ffc;
    BITS[60] = 15;
    CODES[61] = 0x20;
    BITS[61] = 6;
    CODES[62] = 0xffb;
    BITS[62] = 12;
    CODES[63] = 0x3fc;
    BITS[63] = 10;
    CODES[64] = 0x1ffa;
    BITS[64] = 13;
    CODES[65] = 0x21;
    BITS[65] = 6;
    CODES[66] = 0x5d;
    BITS[66] = 7;
    CODES[67] = 0x5e;
    BITS[67] = 7;
    CODES[68] = 0x5f;
    BITS[68] = 7;
    CODES[69] = 0x60;
    BITS[69] = 7;
    CODES[70] = 0x61;
    BITS[70] = 7;
    CODES[71] = 0x62;
    BITS[71] = 7;
    CODES[72] = 0x63;
    BITS[72] = 7;
    CODES[73] = 0x64;
    BITS[73] = 7;
    CODES[74] = 0x65;
    BITS[74] = 7;
    CODES[75] = 0x66;
    BITS[75] = 7;
    CODES[76] = 0x67;
    BITS[76] = 7;
    CODES[77] = 0x68;
    BITS[77] = 7;
    CODES[78] = 0x69;
    BITS[78] = 7;
    CODES[79] = 0x6a;
    BITS[79] = 7;
    CODES[80] = 0x6b;
    BITS[80] = 7;
    CODES[81] = 0x6c;
    BITS[81] = 7;
    CODES[82] = 0x6d;
    BITS[82] = 7;
    CODES[83] = 0x6e;
    BITS[83] = 7;
    CODES[84] = 0x6f;
    BITS[84] = 7;
    CODES[85] = 0x70;
    BITS[85] = 7;
    CODES[86] = 0x71;
    BITS[86] = 7;
    CODES[87] = 0x72;
    BITS[87] = 7;
    CODES[88] = 0xfc;
    BITS[88] = 8;
    CODES[89] = 0x73;
    BITS[89] = 7;
    CODES[90] = 0xfd;
    BITS[90] = 8;
    CODES[91] = 0x1ffb;
    BITS[91] = 13;
    CODES[92] = 0x7fff0;
    BITS[92] = 19;
    CODES[93] = 0x1ffc;
    BITS[93] = 13;
    CODES[94] = 0x3ffc;
    BITS[94] = 14;
    CODES[95] = 0x22;
    BITS[95] = 6;
    CODES[96] = 0x7ffd;
    BITS[96] = 15;
    CODES[97] = 0x3;
    BITS[97] = 5;
    CODES[98] = 0x23;
    BITS[98] = 6;
    CODES[99] = 0x4;
    BITS[99] = 5;
    CODES[100] = 0x24;
    BITS[100] = 6;
    CODES[101] = 0x5;
    BITS[101] = 5;
    CODES[102] = 0x25;
    BITS[102] = 6;
    CODES[103] = 0x26;
    BITS[103] = 6;
    CODES[104] = 0x27;
    BITS[104] = 6;
    CODES[105] = 0x6;
    BITS[105] = 5;
    CODES[106] = 0x74;
    BITS[106] = 7;
    CODES[107] = 0x75;
    BITS[107] = 7;
    CODES[108] = 0x28;
    BITS[108] = 6;
    CODES[109] = 0x29;
    BITS[109] = 6;
    CODES[110] = 0x2a;
    BITS[110] = 6;
    CODES[111] = 0x7;
    BITS[111] = 5;
    CODES[112] = 0x2b;
    BITS[112] = 6;
    CODES[113] = 0x76;
    BITS[113] = 7;
    CODES[114] = 0x2c;
    BITS[114] = 6;
    CODES[115] = 0x8;
    BITS[115] = 5;
    CODES[116] = 0x9;
    BITS[116] = 5;
    CODES[117] = 0x2d;
    BITS[117] = 6;
    CODES[118] = 0x77;
    BITS[118] = 7;
    CODES[119] = 0x78;
    BITS[119] = 7;
    CODES[120] = 0x79;
    BITS[120] = 7;
    CODES[121] = 0x7a;
    BITS[121] = 7;
    CODES[122] = 0x7b;
    BITS[122] = 7;
    CODES[123] = 0x7ffe;
    BITS[123] = 15;
    CODES[124] = 0x7fc;
    BITS[124] = 11;
    CODES[125] = 0x3ffd;
    BITS[125] = 14;
    CODES[126] = 0x1ffd;
    BITS[126] = 13;
    CODES[127] = 0xffffffc;
    BITS[127] = 28;
    CODES[128] = 0xfffe6;
    BITS[128] = 20;
    CODES[129] = 0x3fffd2;
    BITS[129] = 22;
    CODES[130] = 0xfffe7;
    BITS[130] = 20;
    CODES[131] = 0xfffe8;
    BITS[131] = 20;
    CODES[132] = 0x3fffd3;
    BITS[132] = 22;
    CODES[133] = 0x3fffd4;
    BITS[133] = 22;
    CODES[134] = 0x3fffd5;
    BITS[134] = 22;
    CODES[135] = 0x7fffd9;
    BITS[135] = 23;
    CODES[136] = 0x3fffd6;
    BITS[136] = 22;
    CODES[137] = 0x7fffda;
    BITS[137] = 23;
    CODES[138] = 0x7fffdb;
    BITS[138] = 23;
    CODES[139] = 0x7fffdc;
    BITS[139] = 23;
    CODES[140] = 0x7fffdd;
    BITS[140] = 23;
    CODES[141] = 0x7fffde;
    BITS[141] = 23;
    CODES[142] = 0xffffeb;
    BITS[142] = 24;
    CODES[143] = 0x7fffdf;
    BITS[143] = 23;
    CODES[144] = 0xffffec;
    BITS[144] = 24;
    CODES[145] = 0xffffed;
    BITS[145] = 24;
    CODES[146] = 0x3fffd7;
    BITS[146] = 22;
    CODES[147] = 0x7fffe0;
    BITS[147] = 23;
    CODES[148] = 0xffffee;
    BITS[148] = 24;
    CODES[149] = 0x7fffe1;
    BITS[149] = 23;
    CODES[150] = 0x7fffe2;
    BITS[150] = 23;
    CODES[151] = 0x7fffe3;
    BITS[151] = 23;
    CODES[152] = 0x7fffe4;
    BITS[152] = 23;
    CODES[153] = 0x1fffdc;
    BITS[153] = 21;
    CODES[154] = 0x3fffd8;
    BITS[154] = 22;
    CODES[155] = 0x7fffe5;
    BITS[155] = 23;
    CODES[156] = 0x3fffd9;
    BITS[156] = 22;
    CODES[157] = 0x7fffe6;
    BITS[157] = 23;
    CODES[158] = 0x7fffe7;
    BITS[158] = 23;
    CODES[159] = 0xffffef;
    BITS[159] = 24;
    CODES[160] = 0x3fffda;
    BITS[160] = 22;
    CODES[161] = 0x1fffdd;
    BITS[161] = 21;
    CODES[162] = 0xfffe9;
    BITS[162] = 20;
    CODES[163] = 0x3fffdb;
    BITS[163] = 22;
    CODES[164] = 0x3fffdc;
    BITS[164] = 22;
    CODES[165] = 0x7fffe8;
    BITS[165] = 23;
    CODES[166] = 0x7fffe9;
    BITS[166] = 23;
    CODES[167] = 0x1fffde;
    BITS[167] = 21;
    CODES[168] = 0x7fffea;
    BITS[168] = 23;
    CODES[169] = 0x3fffdd;
    BITS[169] = 22;
    CODES[170] = 0x3fffde;
    BITS[170] = 22;
    CODES[171] = 0xfffff0;
    BITS[171] = 24;
    CODES[172] = 0x1fffdf;
    BITS[172] = 21;
    CODES[173] = 0x3fffdf;
    BITS[173] = 22;
    CODES[174] = 0x7fffeb;
    BITS[174] = 23;
    CODES[175] = 0x7fffec;
    BITS[175] = 23;
    CODES[176] = 0x1fffe0;
    BITS[176] = 21;
    CODES[177] = 0x1fffe1;
    BITS[177] = 21;
    CODES[178] = 0x3fffe0;
    BITS[178] = 22;
    CODES[179] = 0x1fffe2;
    BITS[179] = 21;
    CODES[180] = 0x7fffed;
    BITS[180] = 23;
    CODES[181] = 0x3fffe1;
    BITS[181] = 22;
    CODES[182] = 0x7fffee;
    BITS[182] = 23;
    CODES[183] = 0x7fffef;
    BITS[183] = 23;
    CODES[184] = 0xfffea;
    BITS[184] = 20;
    CODES[185] = 0x3fffe2;
    BITS[185] = 22;
    CODES[186] = 0x3fffe3;
    BITS[186] = 22;
    CODES[187] = 0x3fffe4;
    BITS[187] = 22;
    CODES[188] = 0x7ffff0;
    BITS[188] = 23;
    CODES[189] = 0x3fffe5;
    BITS[189] = 22;
    CODES[190] = 0x3fffe6;
    BITS[190] = 22;
    CODES[191] = 0x7ffff1;
    BITS[191] = 23;
    CODES[192] = 0x3ffffe0;
    BITS[192] = 26;
    CODES[193] = 0x3ffffe1;
    BITS[193] = 26;
    CODES[194] = 0xfffeb;
    BITS[194] = 20;
    CODES[195] = 0x7fff1;
    BITS[195] = 19;
    CODES[196] = 0x3fffe7;
    BITS[196] = 22;
    CODES[197] = 0x7ffff2;
    BITS[197] = 23;
    CODES[198] = 0x3fffe8;
    BITS[198] = 22;
    CODES[199] = 0x1ffffec;
    BITS[199] = 25;
    CODES[200] = 0x3ffffe2;
    BITS[200] = 26;
    CODES[201] = 0x3ffffe3;
    BITS[201] = 26;
    CODES[202] = 0x3ffffe4;
    BITS[202] = 26;
    CODES[203] = 0x7ffffde;
    BITS[203] = 27;
    CODES[204] = 0x7ffffdf;
    BITS[204] = 27;
    CODES[205] = 0x3ffffe5;
    BITS[205] = 26;
    CODES[206] = 0xfffff1;
    BITS[206] = 24;
    CODES[207] = 0x1ffffed;
    BITS[207] = 25;
    CODES[208] = 0x7fff2;
    BITS[208] = 19;
    CODES[209] = 0x1fffe3;
    BITS[209] = 21;
    CODES[210] = 0x3ffffe6;
    BITS[210] = 26;
    CODES[211] = 0x7ffffe0;
    BITS[211] = 27;
    CODES[212] = 0x7ffffe1;
    BITS[212] = 27;
    CODES[213] = 0x3ffffe7;
    BITS[213] = 26;
    CODES[214] = 0x7ffffe2;
    BITS[214] = 27;
    CODES[215] = 0xfffff2;
    BITS[215] = 24;
    CODES[216] = 0x1fffe4;
    BITS[216] = 21;
    CODES[217] = 0x1fffe5;
    BITS[217] = 21;
    CODES[218] = 0x3ffffe8;
    BITS[218] = 26;
    CODES[219] = 0x3ffffe9;
    BITS[219] = 26;
    CODES[220] = 0xffffffd;
    BITS[220] = 28;
    CODES[221] = 0x7ffffe3;
    BITS[221] = 27;
    CODES[222] = 0x7ffffe4;
    BITS[222] = 27;
    CODES[223] = 0x7ffffe5;
    BITS[223] = 27;
    CODES[224] = 0xfffec;
    BITS[224] = 20;
    CODES[225] = 0xfffff3;
    BITS[225] = 24;
    CODES[226] = 0xfffed;
    BITS[226] = 20;
    CODES[227] = 0x1fffe6;
    BITS[227] = 21;
    CODES[228] = 0x3fffe9;
    BITS[228] = 22;
    CODES[229] = 0x1fffe7;
    BITS[229] = 21;
    CODES[230] = 0x1fffe8;
    BITS[230] = 21;
    CODES[231] = 0x7ffff3;
    BITS[231] = 23;
    CODES[232] = 0x3fffea;
    BITS[232] = 22;
    CODES[233] = 0x3fffeb;
    BITS[233] = 22;
    CODES[234] = 0x1ffffee;
    BITS[234] = 25;
    CODES[235] = 0x1ffffef;
    BITS[235] = 25;
    CODES[236] = 0xfffff4;
    BITS[236] = 24;
    CODES[237] = 0xfffff5;
    BITS[237] = 24;
    CODES[238] = 0x3ffffea;
    BITS[238] = 26;
    CODES[239] = 0x7ffff4;
    BITS[239] = 23;
    CODES[240] = 0x3ffffeb;
    BITS[240] = 26;
    CODES[241] = 0x7ffffe6;
    BITS[241] = 27;
    CODES[242] = 0x3ffffec;
    BITS[242] = 26;
    CODES[243] = 0x3ffffed;
    BITS[243] = 26;
    CODES[244] = 0x7ffffe7;
    BITS[244] = 27;
    CODES[245] = 0x7ffffe8;
    BITS[245] = 27;
    CODES[246] = 0x7ffffe9;
    BITS[246] = 27;
    CODES[247] = 0x7ffffea;
    BITS[247] = 27;
    CODES[248] = 0x7ffffeb;
    BITS[248] = 27;
    CODES[249] = 0xffffffe;
    BITS[249] = 28;
    CODES[250] = 0x7ffffec;
    BITS[250] = 27;
    CODES[251] = 0x7ffffed;
    BITS[251] = 27;
    CODES[252] = 0x7ffffee;
    BITS[252] = 27;
    CODES[253] = 0x7ffffef;
    BITS[253] = 27;
    CODES[254] = 0x7fffff0;
    BITS[254] = 27;
    CODES[255] = 0x3ffffee;
    BITS[255] = 26;
    CODES[256] = 0x3fffffff;
    BITS[256] = 30;

    for (int i = 0; i < 256; i++) {
      insert(CODES[i], BITS[i], i);
    }
    insert(CODES[256], BITS[256], 256); // EOS
  }

  private HPACKHuffman() {
  }

  public static byte[] encode(byte[] input) {
    long current = 0;
    int n = 0;
    ByteArrayOutputStream out = new ByteArrayOutputStream(input.length);
    for (byte b : input) {
      int sym = b & 0xff;
      int code = CODES[sym];
      int bits = BITS[sym];
      current = (current << bits) | code;
      n += bits;
      while (n >= 8) {
        n -= 8;
        out.write((int) ((current >> n) & 0xff));
      }
    }
    if (n > 0) {
      current = (current << (8 - n)) | (0xff >>> n);
      out.write((int) (current & 0xff));
    }
    return out.toByteArray();
  }

  public static byte[] decode(byte[] input) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(input.length * 2);
    Node node = ROOT;
    int current = 0;
    int nbits = 0;
    for (byte value : input) {
      current = (current << 8) | (value & 0xff);
      nbits += 8;
      while (nbits >= 1) {
        int bit = (current >>> (nbits - 1)) & 1;
        nbits--;
        node = bit == 0 ? node.zero : node.one;
        if (node == null) {
          throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Invalid Huffman sequence");
        }
        if (node.symbol >= 0) {
          if (node.symbol == 256) {
            throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "EOS in Huffman string");
          }
          out.write(node.symbol);
          node = ROOT;
        }
      }
    }
    // Padding must be all 1s (prefix of EOS)
    while (node != ROOT && node.symbol < 0) {
      node = node.one;
      if (node == null) {
        throw new HTTP2Exception(HTTP2ErrorCode.COMPRESSION_ERROR, "Invalid Huffman padding");
      }
    }
    return out.toByteArray();
  }

  public static String decodeString(byte[] input) {
    return new String(decode(input), StandardCharsets.ISO_8859_1);
  }

  private static void insert(int code, int bits, int symbol) {
    Node node = ROOT;
    for (int i = bits - 1; i >= 0; i--) {
      int bit = (code >>> i) & 1;
      if (bit == 0) {
        if (node.zero == null) {
          node.zero = new Node();
        }
        node = node.zero;
      } else {
        if (node.one == null) {
          node.one = new Node();
        }
        node = node.one;
      }
    }
    node.symbol = symbol;
  }

  private static final class Node {
    Node zero;
    Node one;
    int symbol = -1;
  }
}
