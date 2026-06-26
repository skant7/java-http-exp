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
 * Common HTTP/2 frame flags.
 */
public final class HTTP2Flags {
  public static final int END_STREAM = 0x1;
  public static final int ACK = 0x1;
  public static final int END_HEADERS = 0x4;
  public static final int PADDED = 0x8;
  public static final int PRIORITY = 0x20;

  private HTTP2Flags() {
  }

  public static boolean isSet(int flags, int flag) {
    return (flags & flag) != 0;
  }
}
