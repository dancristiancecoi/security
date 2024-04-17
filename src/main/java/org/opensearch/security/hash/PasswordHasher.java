/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.hash;

import java.nio.CharBuffer;

public interface PasswordHasher {
    String hash(CharBuffer password);

    boolean check(CharBuffer password, String hashedPassword);
}
