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
 * A decoded HTTP/2 frame.
 */
public class HTTP2Frame {
  public final int length;
  public final int type;
  public final int flags;
  public final int streamId;
  public final byte[] payload;

  public HTTP2Frame(int length, int type, int flags, int streamId, byte[] payload) {
    this.length = length;
    this.type = type;
    this.flags = flags;
    this.streamId = streamId;
    this.payload = payload;
  }
}
