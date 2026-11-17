/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Verify literal legacy keys against real KV v1/v2 engines. Seed and inspect raw Vault JSON independently
 * of alias parsing, and use fresh stores for reads so cached writes cannot hide an incorrect target.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LegacyAliasIntegrationTestCase {

    private VaultContainer<?> container;

    @BeforeAll
    void startVault() {
        container = new VaultContainer<>(VaultContainerVersion.IMAGE).withVaultToken("myroot")
                .withInitCommand("secrets enable -version=1 -path=legacy-v1 kv",
                        "secrets enable -version=2 -path=legacy-v2 kv");
        container.start();
    }

    @AfterAll
    void stopVault() {
        if (container != null) {
            container.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void testLegacyReadWriteRemoveAndListing(int version) throws Exception {
        Vault vault = rawVault(version);
        List<Arguments> cases = LegacyAliasCompatibilityTestCase.literalKeys().toList();
        for (Arguments args : cases) {
            String key = (String) args.get()[0];
            String encodedKey = (String) args.get()[1];
            writeRaw(vault, version, "app", seed());
            HashicorpVaultCredentialStore store = store(version, true);
            assertEquals("literal:" + key, read(store, "app." + key));

            Map<String, Object> expected = readRaw(vault, version, "app");
            expected.put(key, "changed");
            store.store("app." + key, password("changed"), null);
            assertEquals(expected, readRaw(vault, version, "app"), "Legacy write changed another field: " + key);
            assertEquals("changed", read(store(version, true), "app." + key));
            assertEquals("changed", read(store(version, false), "#app?" + encodedKey));

            // Listing must return an encoded alias for the same literal key, even with legacy support enabled.
            HashicorpVaultCredentialStore reader = store(version, true);
            Set<String> aliases = reader.getAliases("#app");
            assertTrue(aliases.contains("#app?" + encodedKey), aliases.toString());
            assertEquals("changed", read(reader, "#app?" + encodedKey));

            // Start from an independent seed to ensure remove does not rely on the preceding write.
            writeRaw(vault, version, "app", seed());
            expected = readRaw(vault, version, "app");
            expected.remove(key);
            store(version, true).remove("app." + key, PasswordCredential.class, null, null);
            assertEquals(expected, readRaw(vault, version, "app"), "Legacy remove changed another field: " + key);
            assertNull(store(version, true).retrieve("app." + key, PasswordCredential.class, null, null, null));
        }
    }

    static Stream<Arguments> newFormatConfigurations() {
        return Stream.of(Arguments.of(1, false), Arguments.of(1, true), Arguments.of(2, false), Arguments.of(2, true));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void testRemovingLastLiteralKeyDeletesSecretAndEvictsEquivalentAlias(int version) throws Exception {
        Vault vault = rawVault(version);
        writeRaw(vault, version, "last", Map.of("database/host", "literal"));
        HashicorpVaultCredentialStore store = store(version, true);
        assertEquals("literal", read(store, "#last?database%2Fhost"));
        store.remove("last.database/host", PasswordCredential.class, null, null);
        assertEquals(404, vault.logical().read(rawPath(version, "last")).getRestResponse().getStatus());
        assertNull(store.retrieve("#last?database%2Fhost", PasswordCredential.class, null, null, null));
    }

    @ParameterizedTest
    @MethodSource("newFormatConfigurations")
    void testNewFormatReadWriteRemoveWithEitherLegacySetting(int version, boolean legacySupport) throws Exception {
        Vault vault = rawVault(version);
        writeRaw(vault, version, "app", seed());
        HashicorpVaultCredentialStore store = store(version, legacySupport);
        Map<String, String> aliases = Map.of(
                "#app?database/host", "nested",
                "#app?database%2Fhost", "literal:database/host",
                "#app?database%2fhost", "literal:database/host",
                "#app?database%252Fhost", "literal:database%2Fhost",
                "#app?a%2Bb", "literal:a+b",
                "#app?a+b", "literal:a b",
                "#app?a%2520b", "literal:a%20b",
                "#app?parent%2Fdir/child%2Fleaf", "mixed");
        for (Map.Entry<String, String> entry : aliases.entrySet()) {
            assertEquals(entry.getValue(), read(store, entry.getKey()));
        }
        if (!legacySupport) {
            assertThrows(CredentialStoreException.class, () -> read(store, "app.database/host"));
            assertThrows(CredentialStoreException.class,
                    () -> store.store("app.database/host", password("rejected"), null));
            assertThrows(CredentialStoreException.class,
                    () -> store.remove("app.database/host", PasswordCredential.class, null, null));
        }

        // Both a nested path and a literal slash key must remain independently writable and removable.
        for (String alias : List.of("#app?database/host", "#app?database%2Fhost", "#app?parent%2Fdir/child%2Fleaf")) {
            writeRaw(vault, version, "app", seed());
            Map<String, Object> expected = readRaw(vault, version, "app");
            Map<String, Object> target = expected;
            String key = "database/host";
            if (alias.equals("#app?database/host")) {
                target = nested(expected, "database");
                key = "host";
            } else if (alias.equals("#app?parent%2Fdir/child%2Fleaf")) {
                target = nested(expected, "parent/dir");
                key = "child/leaf";
            }
            target.put(key, "changed");
            HashicorpVaultCredentialStore writer = store(version, legacySupport);
            writer.store(alias, password("changed"), null);
            assertEquals(expected, readRaw(vault, version, "app"));
            assertEquals("changed", read(store(version, legacySupport), alias));
            target.remove(key);
            writer.remove(alias, PasswordCredential.class, null, null);
            assertEquals(expected, readRaw(vault, version, "app"));
        }
    }

    private static Map<String, Object> seed() {
        Map<String, Object> data = new HashMap<>();
        LegacyAliasCompatibilityTestCase.literalKeys().forEach(args -> {
            String key = (String) args.get()[0];
            data.put(key, "literal:" + key);
        });
        data.put("database", Json.object().add("host", "nested").add("sibling", "keep"));
        data.put("parent/dir", Json.object().add("child/leaf", "mixed").add("sibling", "keep"));
        data.put("port", 5432);
        data.put("enabled", true);
        data.put("hosts", Json.array("h1", "h2"));
        return data;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nested(Map<String, Object> data, String key) {
        return (Map<String, Object>) data.get(key);
    }

    private Vault rawVault(int version) throws Exception {
        return Vault.create(new VaultConfig().address(container.getHttpHostAddress()).token("myroot")
                .engineVersion(version).build());
    }

    private static String rawPath(int version, String path) {
        return "legacy-v" + version + "/" + path;
    }

    private static void writeRaw(Vault vault, int version, String path, Map<String, Object> data) throws Exception {
        int status = vault.logical().write(rawPath(version, path), data).getRestResponse().getStatus();
        assertTrue(status == 200 || status == 204, "Raw seed failed: HTTP " + status);
    }

    private static Map<String, Object> readRaw(Vault vault, int version, String path) throws Exception {
        var response = vault.logical().read(rawPath(version, path));
        assertEquals(200, response.getRestResponse().getStatus());
        return JsonPath.from(response.getDataObject().toString()).getMap("");
    }

    private HashicorpVaultCredentialStore store(int version, boolean legacySupport) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        store.initialize(Map.of("host-address", container.getHttpHostAddress(),
                        "default-engine-type", "KVv" + version, "default-mount-path", "legacy-v" + version,
                        "support-legacy-alias-format", String.valueOf(legacySupport)),
                new CredentialStore.CredentialSourceProtectionParameter(IdentityCredentials.NONE.withCredential(password("myroot"))),
                new Provider[0]);
        return store;
    }

    private static PasswordCredential password(String value) {
        return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, value.toCharArray()));
    }

    private static String read(HashicorpVaultCredentialStore store, String alias) throws Exception {
        PasswordCredential credential = store.retrieve(alias, PasswordCredential.class, null, null, null);
        assertNotNull(credential, alias);
        return new String(credential.getPassword(ClearPassword.class).getPassword());
    }
}
