/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

/**
 * Verifies that the JVM actually running the tests matches the toolchain requested via
 * {@code -Djdk.test.version} and {@code -Djdk.test.vendor}.
 *
 * <p>The two system properties are injected into the forked surefire JVM via
 * {@code <systemPropertyVariables>} in the POM. When the properties are absent (e.g. a plain
 * {@code mvn test} on a developer machine without toolchain properties) the test is skipped via
 * {@link org.junit.jupiter.api.Assumptions#assumeTrue}.</p>
 *
 * <p>When present the test asserts:</p>
 * <ul>
 *   <li>{@code java.version} starts with the requested major version number.</li>
 *   <li>{@code java.vendor} contains the vendor substring expected for the requested vendor key
 *       ({@code temurin} → {@code "Eclipse Adoptium"}, {@code semeru} → {@code "IBM Corporation"}).</li>
 * </ul>
 */
public class JvmToolchainVerificationTestCase {

    @Test
    public void testExpectedJvmVersionIsRunning() {
        String requestedVersion = System.getProperty("jdk.test.version");
        assumeTrue(requestedVersion != null && !requestedVersion.isEmpty(),
                "jdk.test.version not set – skipping toolchain verification");

        String actualVersion = System.getProperty("java.version");
        assertTrue(actualVersion.startsWith(requestedVersion + ".") || actualVersion.equals(requestedVersion),
                "Expected JVM version " + requestedVersion + " but running on " + actualVersion
                        + " (java.vendor=" + System.getProperty("java.vendor") + ")");
    }

    @Test
    public void testExpectedJvmVendorIsRunning() {
        String requestedVendor = System.getProperty("jdk.test.vendor");
        assumeTrue(requestedVendor != null && !requestedVendor.isEmpty(),
                "jdk.test.vendor not set – skipping toolchain verification");

        String actualVendor = System.getProperty("java.vendor");
        String expectedVendorSubstring = expectedVendorSubstring(requestedVendor);

        assertTrue(actualVendor.contains(expectedVendorSubstring),
                "Expected JVM vendor key '" + requestedVendor + "' (substring '" + expectedVendorSubstring
                        + "') but java.vendor='" + actualVendor + "'"
                        + " (java.version=" + System.getProperty("java.version") + ")");
    }

    /**
     * Maps the Maven toolchain vendor key used in {@code jdk.test.vendor} to the substring that
     * appears in the {@code java.vendor} system property of the corresponding JVM.
     *
     * <ul>
     *   <li>{@code temurin}  → {@code "Eclipse Adoptium"}</li>
     *   <li>{@code semeru}   → {@code "IBM Corporation"}</li>
     * </ul>
     *
     * If an unrecognised key is supplied the test fails immediately so that any future vendor
     * additions are forced to be reflected here.
     */
    private static String expectedVendorSubstring(String vendorKey) {
        switch (vendorKey.toLowerCase()) {
            case "temurin":
                return "Eclipse Adoptium";
            case "semeru":
                return "IBM Corporation";
            default:
                throw new AssertionError("Unrecognised jdk.test.vendor value '" + vendorKey
                        + "'. Add the expected java.vendor substring for this vendor key.");
        }
    }
}
