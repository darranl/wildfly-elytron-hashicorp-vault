/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import io.github.jopenlibs.vault.SslConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Legacy keys follow 1.0.1.Final's literal map lookup, independently of the new format's escaping rules.
 * These tests deliberately seed both interpretations with different values.
 */
public class LegacyAliasCompatibilityTestCase {

    static Stream<Arguments> literalKeys() {
        // Literal key and its equivalent new-format key spelling; do not derive expectations with the encoder.
        return Stream.of(
                Arguments.of("database/host", "database%2Fhost"),
                Arguments.of("database%2Fhost", "database%252Fhost"),
                Arguments.of("database%2fhost", "database%252fhost"),
                Arguments.of("database%252Fhost", "database%25252Fhost"),
                Arguments.of("a+b", "a%2Bb"),
                Arguments.of("a%2Bb", "a%252Bb"),
                Arguments.of("a%20b", "a%2520b"),
                Arguments.of("a b", "a%20b"),
                Arguments.of("100%", "100%25"),
                Arguments.of("a%zz", "a%25zz"),
                Arguments.of("a%20b%zz", "a%2520b%25zz"),
                Arguments.of("/leading", "%2Fleading"),
                Arguments.of("trailing/", "trailing%2F"),
                Arguments.of("a//b", "a%2F%2Fb"),
                Arguments.of("/", "%2F"),
                Arguments.of("//", "%2F%2F"),
                Arguments.of("a@b", "a%40b"),
                Arguments.of("a#b", "a%23b"),
                Arguments.of("a?b", "a%3Fb"),
                Arguments.of("café", "caf%C3%A9"));
    }

    private static Map<String, Object> seed() {
        Map<String, Object> data = new HashMap<>();
        literalKeys().forEach(args -> {
            String key = (String) args.get()[0];
            data.put(key, "literal:" + key);
        });
        data.put("database", Map.of("host", "nested"));
        data.put("a", Map.of("b", "other-nested"));
        return data;
    }

    @ParameterizedTest
    @MethodSource("literalKeys")
    void testLegacyKeyIsOneLiteralSegment(String key, String encodedKey) throws Exception {
        VaultAlias legacy = VaultAlias.parse("app." + key, "KVv2", "secret", true);
        assertEquals(List.of(key), legacy.getKeyPathSegments());
        assertEquals(key, legacy.getKeyPath());
        assertEquals("literal:" + key, VaultKeyPathOperations.resolveKeyPathSegments(seed(), legacy.getKeyPathSegments()));

        VaultAlias equivalent = VaultAlias.parse("#app?" + encodedKey);
        assertEquals(equivalent, legacy);
        assertEquals(equivalent.hashCode(), legacy.hashCode());
    }

    @ParameterizedTest
    @MethodSource("literalKeys")
    void testLegacyWriteAndRemovePreserveAllOtherKeys(String key, String encodedKey) throws Exception {
        VaultAlias alias = VaultAlias.parse("app." + key, "KVv2", "secret", true);
        Map<String, Object> data = seed();
        Map<String, Object> expected = seed();
        expected.put(key, "updated");
        VaultKeyPathOperations.setNestedValueSegments(data, alias.getKeyPathSegments(), "updated");
        assertEquals(expected, data, "Only the literal top-level key should change");

        data = seed();
        expected = seed();
        expected.remove(key);
        VaultKeyPathOperations.removeNestedValueSegments(data, alias.getKeyPathSegments());
        assertEquals(expected, data, "Only the literal top-level key should be removed");
    }

    @ParameterizedTest
    @MethodSource("literalKeys")
    @SuppressWarnings("deprecation")
    void testDeprecatedCredentialSourceUsesLiteralKey(String key, String encodedKey) throws Exception {
        VaultCredentialSource source = new VaultCredentialSource(connector(seed(), new AtomicInteger()), "secret/app", key);
        PasswordCredential credential = source.getCredential(PasswordCredential.class, null, null);
        assertNotNull(credential);
        assertEquals("literal:" + key, value(credential));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testNewFormatSemanticsDoNotDependOnLegacySupport(boolean legacySupport) throws Exception {
        Map<String, Object> data = seed();
        Map<String, String> aliases = Map.of(
                "#app?database/host", "nested",
                "#app?database%2Fhost", "literal:database/host",
                "#app?database%2fhost", "literal:database/host",
                "#app?database%252Fhost", "literal:database%2Fhost",
                "#app?a+b", "literal:a b",
                "#app?a%2Bb", "literal:a+b",
                "#app?a%2520b", "literal:a%20b");
        for (Map.Entry<String, String> entry : aliases.entrySet()) {
            VaultAlias alias = VaultAlias.parse(entry.getKey(), "KVv2", "secret", legacySupport);
            assertEquals(entry.getValue(), VaultKeyPathOperations.resolveKeyPathSegments(data, alias.getKeyPathSegments()));
        }
        assertEquals("app name", VaultAlias.parse("#app+name?key", "KVv2", "secret", legacySupport).getSecretPath());
        assertThrows(CredentialStoreException.class,
                () -> VaultAlias.parse("#app?a//b", "KVv2", "secret", legacySupport));
        assertThrows(CredentialStoreException.class,
                () -> VaultAlias.parse("#app?trailing/", "KVv2", "secret", legacySupport));
    }

    static Stream<Arguments> unambiguousLiteralKeys() {
        return literalKeys().filter(args -> !((String) args.get()[0]).contains("?"));
    }

    @ParameterizedTest
    @MethodSource("unambiguousLiteralKeys")
    void testRejectedLegacyAliasSuggestsEquivalentNewAlias(String key, String encodedKey) {
        CredentialStoreException exception = assertThrows(CredentialStoreException.class,
                () -> VaultAlias.parse("app." + key, "KVv2", "secret", false));
        assertTrue(exception.getMessage().contains("#app?" + encodedKey), exception.getMessage());
    }

    @Test
    void testCacheSharesEquivalentAliasesButDistinguishesNestedKeys() throws Exception {
        Map<String, Object> data = seed();
        AtomicInteger reads = new AtomicInteger();
        HashicorpVaultCredentialStore store = store(data, reads, true);
        PasswordCredential literal = retrieve(store, "app.database/host");
        assertEquals("literal:database/host", value(literal));
        assertSame(literal, retrieve(store, "#app?database%2Fhost"));
        assertEquals(1, reads.get());
        assertEquals("nested", value(retrieve(store, "#app?database/host")));
        assertEquals("literal:database%2Fhost", value(retrieve(store, "app.database%2Fhost")));
        assertEquals(3, reads.get());
        assertNotEquals(VaultAlias.parse("#app?database/host"), VaultAlias.parse("#app?database%2Fhost"));

        store.store("app.database/host", password("updated"), null);
        assertEquals("updated", value(retrieve(store, "#app?database%2Fhost")));
        assertEquals("nested", value(retrieve(store, "#app?database/host")));
        store.remove("#app?database%2Fhost", PasswordCredential.class, null, null);
        assertNull(retrieve(store, "app.database/host"));
        assertEquals("nested", value(retrieve(store, "#app?database/host")));

        store.store("#app?database%2Fhost", password("restored"), null);
        store.remove("app.database/host", PasswordCredential.class, null, null);
        assertNull(retrieve(store, "#app?database%2Fhost"));
    }

    @Test
    void testMissingLiteralKeyDoesNotFallBackToNestedValue() throws Exception {
        Map<String, Object> data = new HashMap<>(Map.of("database", Map.of("host", "nested")));
        HashicorpVaultCredentialStore store = store(data, new AtomicInteger(), true);
        assertNull(retrieve(store, "app.database/host"));
        store.remove("app.database/host", PasswordCredential.class, null, null);
        assertEquals(Map.of("database", Map.of("host", "nested")), data);
    }

    @Test
    void testExplicitComponentConstructorRetainsNestedPathSemantics() throws Exception {
        VaultConnector connector = connector(seed(), new AtomicInteger());
        VaultCredentialSource nested = new VaultCredentialSource(connector, "KVv2", "secret", "app", "database/host");
        assertEquals("nested", value(nested.getCredential(PasswordCredential.class, null, null)));
        VaultCredentialSource literalPercent = new VaultCredentialSource(connector, "KVv2", "secret", "app", "database%2Fhost");
        assertEquals("literal:database%2Fhost", value(literalPercent.getCredential(PasswordCredential.class, null, null)));
    }

    @Test
    void testMigrationSuggestionPreservesEncodedSecretPath() {
        CredentialStoreException exception = assertThrows(CredentialStoreException.class,
                () -> VaultAlias.parse("app%20name.key/part", "KVv2", "secret", false));
        assertTrue(exception.getMessage().contains("#app%20name?key%2Fpart"), exception.getMessage());
    }

    @Test
    void testAmbiguousAliasUsesLegacyOnlyWhenEnabled() throws Exception {
        VaultAlias legacy = VaultAlias.parse("secret/app.a?b", "KVv2", "other", true);
        assertEquals("secret", legacy.getMountPath());
        assertEquals("app", legacy.getSecretPath());
        assertEquals(List.of("a?b"), legacy.getKeyPathSegments());
        VaultAlias modern = VaultAlias.parse("secret/app.a?b", "KVv2", "other", false);
        assertEquals("other", modern.getMountPath());
        assertEquals("secret/app.a", modern.getSecretPath());
        assertEquals(List.of("b"), modern.getKeyPathSegments());
        for (boolean enabled : List.of(false, true)) {
            assertEquals(legacy, VaultAlias.parse("@secret#app?a%3Fb", "KVv2", "other", enabled));
            assertEquals(modern, VaultAlias.parse("@other#secret/app.a?b", "KVv2", "other", enabled));
        }
    }

    @Test
    void testQueryRemainsDistinctFromUnversionedAlias() throws Exception {
        VaultAlias versioned = VaultAlias.parse("secret/app?version=1.key", "KVv2", "other", true);
        VaultAlias unversioned = VaultAlias.parse("@secret#app?key");
        assertNotEquals(versioned, unversioned);
        assertEquals("version=1", versioned.getLegacyQuery());
        assertEquals("app", versioned.getSecretPath());
        assertEquals("secret/app?version=1", connector(seed(), new AtomicInteger()).constructVaultPath(versioned));
        VaultAlias encodedQuestion = VaultAlias.parse("secret/app%3Fversion=1.key", "KVv2", "other", true);
        assertNull(encodedQuestion.getLegacyQuery());
        assertEquals("app?version=1", encodedQuestion.getSecretPath());
    }

    private static VaultConnector connector(Map<String, Object> data, AtomicInteger reads) {
        return new VaultConnector("http://dummy", "token", null, new SslConfig(), true) {
            @Override
            public void configure() {
            }

            @Override
            public Map<String, Object> getSecretData(VaultPath path) {
                assertEquals("secret", path.getMountPath());
                assertEquals("app", path.getSecretPath());
                reads.incrementAndGet();
                return data;
            }

            @Override
            Map<String, Object> putSecretData(VaultAlias alias, String value) throws CredentialStoreException {
                VaultKeyPathOperations.setNestedValueSegments(data, alias.getKeyPathSegments(), value);
                return data;
            }

            @Override
            void removeSecretData(VaultAlias alias) throws CredentialStoreException {
                VaultKeyPathOperations.removeNestedValueSegments(data, alias.getKeyPathSegments());
            }
        };
    }

    private static HashicorpVaultCredentialStore store(Map<String, Object> data, AtomicInteger reads, boolean legacySupport)
            throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        store.initialize(Map.of("host-address", "http://dummy", "support-legacy-alias-format", String.valueOf(legacySupport)),
                new CredentialStore.CredentialSourceProtectionParameter(IdentityCredentials.NONE.withCredential(password("token"))),
                new Provider[0]);
        store.vaultConnector = connector(data, reads);
        return store;
    }

    private static PasswordCredential retrieve(HashicorpVaultCredentialStore store, String alias) throws Exception {
        return store.retrieve(alias, PasswordCredential.class, null, null, null);
    }

    private static PasswordCredential password(String value) {
        return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, value.toCharArray()));
    }

    private static String value(PasswordCredential credential) {
        return new String(credential.getPassword(ClearPassword.class).getPassword());
    }
}
