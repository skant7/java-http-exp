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
 * HPACK static table (RFC 7541 Appendix A).
 */
public final class HPACKStaticTable {
  public static final int LENGTH = 61;

  public static final String[] NAMES = new String[LENGTH + 1];
  public static final String[] VALUES = new String[LENGTH + 1];

  static {
    NAMES[1] = ":authority";
    VALUES[1] = "";
    NAMES[2] = ":method";
    VALUES[2] = "GET";
    NAMES[3] = ":method";
    VALUES[3] = "POST";
    NAMES[4] = ":path";
    VALUES[4] = "/";
    NAMES[5] = ":path";
    VALUES[5] = "/index.html";
    NAMES[6] = ":scheme";
    VALUES[6] = "http";
    NAMES[7] = ":scheme";
    VALUES[7] = "https";
    NAMES[8] = ":status";
    VALUES[8] = "200";
    NAMES[9] = ":status";
    VALUES[9] = "204";
    NAMES[10] = ":status";
    VALUES[10] = "206";
    NAMES[11] = ":status";
    VALUES[11] = "304";
    NAMES[12] = ":status";
    VALUES[12] = "400";
    NAMES[13] = ":status";
    VALUES[13] = "404";
    NAMES[14] = ":status";
    VALUES[14] = "500";
    NAMES[15] = "accept-charset";
    VALUES[15] = "";
    NAMES[16] = "accept-encoding";
    VALUES[16] = "gzip, deflate";
    NAMES[17] = "accept-language";
    VALUES[17] = "";
    NAMES[18] = "accept-ranges";
    VALUES[18] = "";
    NAMES[19] = "accept";
    VALUES[19] = "";
    NAMES[20] = "access-control-allow-origin";
    VALUES[20] = "";
    NAMES[21] = "age";
    VALUES[21] = "";
    NAMES[22] = "allow";
    VALUES[22] = "";
    NAMES[23] = "authorization";
    VALUES[23] = "";
    NAMES[24] = "cache-control";
    VALUES[24] = "";
    NAMES[25] = "content-disposition";
    VALUES[25] = "";
    NAMES[26] = "content-encoding";
    VALUES[26] = "";
    NAMES[27] = "content-language";
    VALUES[27] = "";
    NAMES[28] = "content-length";
    VALUES[28] = "";
    NAMES[29] = "content-location";
    VALUES[29] = "";
    NAMES[30] = "content-range";
    VALUES[30] = "";
    NAMES[31] = "content-type";
    VALUES[31] = "";
    NAMES[32] = "cookie";
    VALUES[32] = "";
    NAMES[33] = "date";
    VALUES[33] = "";
    NAMES[34] = "etag";
    VALUES[34] = "";
    NAMES[35] = "expect";
    VALUES[35] = "";
    NAMES[36] = "expires";
    VALUES[36] = "";
    NAMES[37] = "from";
    VALUES[37] = "";
    NAMES[38] = "host";
    VALUES[38] = "";
    NAMES[39] = "if-match";
    VALUES[39] = "";
    NAMES[40] = "if-modified-since";
    VALUES[40] = "";
    NAMES[41] = "if-none-match";
    VALUES[41] = "";
    NAMES[42] = "if-range";
    VALUES[42] = "";
    NAMES[43] = "if-unmodified-since";
    VALUES[43] = "";
    NAMES[44] = "last-modified";
    VALUES[44] = "";
    NAMES[45] = "link";
    VALUES[45] = "";
    NAMES[46] = "location";
    VALUES[46] = "";
    NAMES[47] = "max-forwards";
    VALUES[47] = "";
    NAMES[48] = "proxy-authenticate";
    VALUES[48] = "";
    NAMES[49] = "proxy-authorization";
    VALUES[49] = "";
    NAMES[50] = "range";
    VALUES[50] = "";
    NAMES[51] = "referer";
    VALUES[51] = "";
    NAMES[52] = "refresh";
    VALUES[52] = "";
    NAMES[53] = "retry-after";
    VALUES[53] = "";
    NAMES[54] = "server";
    VALUES[54] = "";
    NAMES[55] = "set-cookie";
    VALUES[55] = "";
    NAMES[56] = "strict-transport-security";
    VALUES[56] = "";
    NAMES[57] = "transfer-encoding";
    VALUES[57] = "";
    NAMES[58] = "user-agent";
    VALUES[58] = "";
    NAMES[59] = "vary";
    VALUES[59] = "";
    NAMES[60] = "via";
    VALUES[60] = "";
    NAMES[61] = "www-authenticate";
    VALUES[61] = "";
  }

  private HPACKStaticTable() {
  }

  public static int findExact(String name, String value) {
    for (int i = 1; i <= LENGTH; i++) {
      if (NAMES[i].equals(name) && VALUES[i].equals(value)) {
        return i;
      }
    }
    return -1;
  }

  public static int findName(String name) {
    for (int i = 1; i <= LENGTH; i++) {
      if (NAMES[i].equals(name)) {
        return i;
      }
    }
    return -1;
  }
}
