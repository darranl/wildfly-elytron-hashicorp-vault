/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Unit tests for {@link VaultAlias#equals(Object)} and {@link VaultAlias#hashCode()}.
 *
 * <p>Verifies that two different alias strings which parse to the same canonical
 * components are considered equal and produce the same hash code, while aliases
 * that differ in any meaningful field are not equal.
 */
public class VaultAliasEqualsHashCodeTestCase {

    // -------------------------------------------------------------------------
    // Equality: same canonical form
    // -------------------------------------------------------------------------

    /**
     * Alias with explicit defaults is equal to the same alias using implicit defaults.
     */
    @Test
    void testExplicitDefaultsEqualsImplicitDefaults() throws CredentialStoreException {
        VaultAlias explicit = VaultAlias.parse("engine=KVv2@secret#myapp?password");
        VaultAlias implicit = VaultAlias.parse("#myapp?password");

        assertEquals(explicit, implicit);
        assertEquals(explicit.hashCode(), implicit.hashCode());
    }

    /**
     * Alias with explicit {@code @mount} equals one that omits it when the default mount matches.
     */
    @Test
    void testExplicitMountEqualsImplicitMount() throws CredentialStoreException {
        VaultAlias withMount = VaultAlias.parse("@secret#testing1?top_secret");
        VaultAlias withoutMount = VaultAlias.parse("#testing1?top_secret");

        assertEquals(withMount, withoutMount);
        assertEquals(withMount.hashCode(), withoutMount.hashCode());
    }

    /**
     * Alias with explicit engine type equals one that omits it when the default engine matches.
     */
    @Test
    void testExplicitEngineEqualsImplicitEngine() throws CredentialStoreException {
        VaultAlias withEngine = VaultAlias.parse("engine=KVv2#myapp?key");
        VaultAlias withoutEngine = VaultAlias.parse("#myapp?key");

        assertEquals(withEngine, withoutEngine);
        assertEquals(withEngine.hashCode(), withoutEngine.hashCode());
    }

    /**
     * Full explicit form with all defaults specified equals minimal form.
     */
    @Test
    void testFullyExplicitEqualsMinimal() throws CredentialStoreException {
        VaultAlias full = VaultAlias.parse("engine=KVv2@secret#myapp/db?password");
        VaultAlias minimal = VaultAlias.parse("myapp/db?password");

        assertEquals(full, minimal);
        assertEquals(full.hashCode(), minimal.hashCode());
    }

    // -------------------------------------------------------------------------
    // Inequality: fields differ
    // -------------------------------------------------------------------------

    /**
     * Aliases with different key paths are not equal.
     */
    @Test
    void testDifferentKeyPathNotEqual() throws CredentialStoreException {
        VaultAlias a = VaultAlias.parse("#myapp?password");
        VaultAlias b = VaultAlias.parse("#myapp?username");

        assertNotEquals(a, b);
    }

    /**
     * Aliases with different secret paths are not equal.
     */
    @Test
    void testDifferentSecretPathNotEqual() throws CredentialStoreException {
        VaultAlias a = VaultAlias.parse("#myapp?password");
        VaultAlias b = VaultAlias.parse("#otherapp?password");

        assertNotEquals(a, b);
    }

    /**
     * Aliases with different mount paths are not equal.
     */
    @Test
    void testDifferentMountPathNotEqual() throws CredentialStoreException {
        VaultAlias a = VaultAlias.parse("@secret#myapp?password");
        VaultAlias b = VaultAlias.parse("@other-mount#myapp?password");

        assertNotEquals(a, b);
    }

    /**
     * Aliases with different engine types are not equal.
     */
    @Test
    void testDifferentEngineTypeNotEqual() throws CredentialStoreException {
        VaultAlias a = VaultAlias.parse("engine=KVv1@secret#myapp?password");
        VaultAlias b = VaultAlias.parse("engine=KVv2@secret#myapp?password");

        assertNotEquals(a, b);
    }

    // -------------------------------------------------------------------------
    // URL-encoded aliases
    // -------------------------------------------------------------------------

    /**
     * A URL-encoded alias is equal to its decoded equivalent after parsing.
     * Both should produce the same canonical components.
     */
    @Test
    void testUrlEncodedAliasEqualsDecoded() throws CredentialStoreException {
        VaultAlias encoded = VaultAlias.parse("#myapp%2Fdb?password");
        VaultAlias decoded = VaultAlias.parse("#myapp/db?password");

        assertEquals(encoded, decoded);
        assertEquals(encoded.hashCode(), decoded.hashCode());
    }
}
