/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Integration tests verifying that the credential cache correctly uses the parsed {@link VaultAlias}
 */
public class VaultAliasCachingTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * Retrieve using the minimal alias form, then retrieve using the fully-explicit form.
     * Both forms parse to the same {@link VaultAlias}.
     */
    @Test
    public void testEquivalentAliasStringsShareCacheEntry() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        // Default engine (KVv2) and default mount (secret)
        PasswordCredential first = store.retrieve(
                "#testing1?top_secret", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(first);

        // Same logical alias, different string
        PasswordCredential second = store.retrieve(
                "engine=KVv2@secret#testing1?top_secret", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(second);

        // Same cached instance, proves the cache was hit.
        assertSame(first, second);
    }

    /**
     * Retrieve using the {@code @mount} form, then retrieve using the minimal form.
     * Both resolve to the same {@link VaultAlias}.
     */
    @Test
    public void testMountPrefixFormSharesCacheEntryWithMinimalForm() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        // Explicit @mount prefix
        PasswordCredential first = store.retrieve(
                "@secret#testing1?top_secret", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(first);

        // Without @mount prefix
        PasswordCredential second = store.retrieve(
                "#testing1?top_secret", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(second);

        assertSame(first, second);
    }

    /**
     * Store via one alias form, then verify retrieve via an equivalent form returns a cache hit.
     *
     * <p>After {@code store()}, the credential is placed in the cache under the parsed
     * {@link VaultAlias} key. A subsequent {@code retrieve()} with a different but equivalent
     * alias string must find that entry.
     */
    @Test
    public void testStoreViaOneFormCachesForEquivalentForm() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        PasswordCredential stored = createCredentialFromPassword("cachedValue");

        // Store using the minimal form
        store.store("#cachealiascheck?key1", stored, null);

        // Retrieve using the fully-explicit equivalent form — should hit the cache
        PasswordCredential retrieved = store.retrieve(
                "engine=KVv2@secret#cachealiascheck?key1", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(retrieved);

        assertSame(stored, retrieved);
    }

    /**
     * Remove via one alias form must also evict the cache entry reachable via an equivalent form.
     */
    @Test
    public void testRemoveViaEquivalentFormEvictsCache() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        // Store and prime the cache via the minimal form
        store.store("#removetest?key1", createCredentialFromPassword("value1"), null);
        store.retrieve("#removetest?key1", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);

        // Remove via the fully-explicit equivalent form
        store.remove("engine=KVv2@secret#removetest?key1",
                PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);

        // Subsequent retrieve (any form) must return null (nothing in Vault or cache)
        PasswordCredential afterRemove = store.retrieve(
                "#removetest?key1", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNull(afterRemove);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private HashicorpVaultCredentialStore createStore() throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        store.initialize(attributes,
                new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(
                                createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(
                    ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(
                    passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }
}
