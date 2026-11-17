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
import java.util.stream.Stream;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
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
import org.testcontainers.vault.VaultContainer;

/**
 * Frozen upgrade contract from 1.0.1.Final (release tag, commit e545183), not the intervening release candidates.
 * The KV v2 destinations were independently verified with that release and its original 6.2.1 driver.
 * The regular suite needs neither a historical checkout nor historical dependencies: it seeds the
 * observed wire destinations directly, then checks the upgraded public store against real Vault.
 * KV v1 exercises the same routing contract with the configurable engine added after Final.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LegacyAliasUpgradeTestCase {
    private VaultContainer<?> container;

    // Legacy suffix, HTTP-encoded secret path, literal key, explicitly encoded modern key.
    // Keep these expectations independent of the production decoder and alias renderer.
    private static final List<List<String>> FINAL_CASES = List.of(
            List.of("app.key", "app", "key", "key"),
            List.of("team/app.key", "team/app", "key", "key"),
            List.of("app.database/host", "app", "database/host", "database%2Fhost"),
            List.of("app.database%2Fhost", "app", "database%2Fhost", "database%252Fhost"),
            List.of("app.a+b", "app", "a+b", "a%2Bb"),
            List.of("app.a%20b", "app", "a%20b", "a%2520b"),
            List.of("app.a@b", "app", "a@b", "a%40b"),
            List.of("app.a#b", "app", "a#b", "a%23b"),
            List.of("app.a?b", "app", "a?b", "a%3Fb"),
            List.of("app.key.", "app", "key", "key"),
            List.of("app.key..", "app", "key", "key"),
            List.of("app?ignored=1.key", "app", "key", "key"),
            List.of("app#ignored.key", "app", "key", "key"),
            List.of("app%3Fname.key", "app%3Fname", "key", "key"),
            List.of("app%23name.key", "app%23name", "key", "key"),
            List.of("app+name.key", "app%2Bname", "key", "key"),
            List.of("app%20name.key", "app%20name", "key", "key"),
            List.of("app%2520name.key", "app%2520name", "key", "key"));

    @BeforeAll
    void startVault() {
        container = new VaultContainer<>(VaultContainerVersion.IMAGE).withVaultToken("myroot")
                .withInitCommand("secrets enable -version=1 -path=upgrade-v1 kv",
                        "secrets enable -version=1 -path=alternate-v1 kv",
                        "secrets enable -version=2 -path=upgrade-v2 kv",
                        "secrets enable -version=2 -path=alternate-v2 kv",
                        "secrets enable -version=2 -path=@legacy-v2 kv",
                        "secrets enable -version=2 -path=engine=legacy-v2 kv");
        container.start();
    }

    @AfterAll
    void stopVault() {
        if (container != null) container.stop();
    }

    static Stream<Arguments> upgradeCases() {
        return Stream.of(1, 2).flatMap(version -> Stream.of(false, true).flatMap(alternate ->
                FINAL_CASES.stream().map(row -> Arguments.of(version, alternate, row))));
    }

    @ParameterizedTest(name = "KV{0}, alternate mount={1}: {2}")
    @MethodSource("upgradeCases")
    void testUnchangedFinalAliasReadsWritesAndRemovesSameCredential(int version, boolean alternate, List<String> row)
            throws Exception {
        String mount = (alternate ? "alternate-v" : "upgrade-v") + version;
        exerciseUpgrade(version, mount, mount, row);
    }

    static Stream<Arguments> reservedMountCases() {
        return Stream.of(List.of("@legacy-v2", "%40legacy-v2"), List.of("engine=legacy-v2", "engine%3Dlegacy-v2"))
                .flatMap(mount -> FINAL_CASES.stream().map(row -> Arguments.of(mount.get(0), mount.get(1), row)));
    }

    @ParameterizedTest
    @MethodSource("reservedMountCases")
    void testFinalMountNameIsNotAnIncompleteModernPrefix(String mount, String encodedMount, List<String> row)
            throws Exception {
        exerciseUpgrade(2, mount, encodedMount, row);
    }

    private void exerciseUpgrade(int version, String mount, String encodedMount, List<String> row) throws Exception {
        Vault vault = rawVault(version);
        String rawPath = mount + "/" + row.get(1);
        String wrongPath = "upgrade-v" + version + "/" + rawPath;
        String alias = mount + "/" + row.get(0);
        String modern = "@" + encodedMount + "#" + row.get(1) + "?" + row.get(3);
        Map<String, Object> expected = new HashMap<>(Map.of(row.get(2), "original", "sibling", "keep"));
        Map<String, Object> wrong = Map.of(row.get(2), "wrong destination", "sibling", "untouched");
        write(vault, rawPath, expected);
        Map<String, Map<String, Object>> untouched = new HashMap<>();
        untouched.put(wrongPath, wrong);
        // Catch form decoding of literal '+' and double encoding of percent escapes.
        if (row.get(0).startsWith("app+name")) untouched.put(mount + "/app%20name", wrong);
        if (row.get(0).startsWith("app%20name")) untouched.put(mount + "/app%2520name", wrong);
        if (row.get(0).startsWith("app%2520name")) untouched.put(mount + "/app%252520name", wrong);
        if (row.get(2).equals("a?b")) untouched.put(mount + "/app.a", Map.of("b", "wrong interpretation"));
        for (var entry : untouched.entrySet()) write(vault, entry.getKey(), entry.getValue());

        HashicorpVaultCredentialStore store = store(version, true);
        assertEquals("original", read(store, alias));
        for (String prefix : List.of("/", "//", "///")) {
            assertEquals("original", read(store(version, true), prefix + alias));
        }
        for (boolean legacy : List.of(false, true)) {
            assertEquals("original", read(store(version, legacy), modern));
        }
        if (row.get(0).equals("app.key")) {
            assertEquals("original", read(store(version, true), mount + "///app.key"));
        }
        // Equivalent aliases must share invalidation, including when warmed through the modern spelling.
        assertEquals("original", read(store, modern));
        String mutationAlias = row.get(0).equals("team/app.key") ? mount + "///team//app.key" : alias;
        store.store(mutationAlias, password("updated"), null);
        expected.put(row.get(2), "updated");
        assertEquals(expected, vault.logical().read(rawPath).getData());
        assertUntouched(vault, untouched);
        assertEquals("updated", read(store, modern));
        assertEquals("updated", read(store(version, true), alias));
        assertEquals("updated", read(store(version, false), modern));
        store.remove(mutationAlias, PasswordCredential.class, null, null);
        expected.remove(row.get(2));
        assertEquals(expected, vault.logical().read(rawPath).getData());
        assertUntouched(vault, untouched);
        assertNull(store.retrieve(modern, PasswordCredential.class, null, null, null));
        assertNull(store(version, true).retrieve(alias, PasswordCredential.class, null, null, null));
        assertEquals("keep", read(store(version, false), "@" + mount + "#" + row.get(1) + "?sibling"));
        // Rejection guidance must route to Final's destination, including encoded paths and literal keys.
        if (!alias.contains("?")) {
            CredentialStoreException rejected = assertThrows(CredentialStoreException.class,
                    () -> store(version, false).retrieve(alias, PasswordCredential.class, null, null, null));
            assertTrue(rejected.getMessage().contains(modern), rejected.getMessage());
        }
    }

    static Stream<Arguments> sourceCases() {
        return FINAL_CASES.stream().filter(row -> !row.get(0).endsWith(".")).map(Arguments::of);
    }

    @SuppressWarnings("deprecation")
    @ParameterizedTest
    @MethodSource("sourceCases")
    void testDeprecatedSourceRetainsFinalWirePathAndLiteralKey(List<String> row) throws Exception {
        Vault vault = rawVault(2);
        String expected = "source:" + row.get(1) + ":" + row.get(2);
        write(vault, "upgrade-v2/" + row.get(1), Map.of(row.get(2), expected));
        if (row.get(0).startsWith("app+name")) write(vault, "upgrade-v2/app%20name", Map.of("key", "wrong"));
        if (row.get(0).startsWith("app%20name")) write(vault, "upgrade-v2/app%2520name", Map.of("key", "wrong"));
        if (row.get(0).startsWith("app%2520name")) write(vault, "upgrade-v2/app%252520name", Map.of("key", "wrong"));
        String legacyPath = "upgrade-v2/" + row.get(0).substring(0, row.get(0).indexOf('.'));
        VaultConnector connector = new VaultConnector(container.getHttpHostAddress(), "myroot", null, new SslConfig(), true);
        for (String path : List.of(legacyPath, "/" + legacyPath, "//" + legacyPath, "///" + legacyPath)) {
            VaultCredentialSource source = new VaultCredentialSource(connector, path, row.get(2));
            PasswordCredential credential = source.getCredential(PasswordCredential.class, null, null);
            assertNotNull(credential);
            assertEquals(expected, new String(credential.getPassword(ClearPassword.class).getPassword()));
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    void testFinalQuerySelectsHistoricalVersionWithoutPollutingLatestCredential() throws Exception {
        Vault vault = rawVault(2);
        // Use a new secret for this test: version=1 must not depend on invocation order.
        write(vault, "upgrade-v2/version-selection", Map.of("key", "first", "sibling", "first sibling"));
        write(vault, "upgrade-v2/version-selection", Map.of("key", "latest", "sibling", "latest sibling"));
        String legacy = "upgrade-v2/version-selection?version=1.key";
        String modern = "@upgrade-v2#version-selection?key";
        HashicorpVaultCredentialStore store = store(2, true);
        assertEquals("latest", read(store, modern));
        assertEquals("first", read(store, legacy));
        assertEquals("latest", read(store, modern));
        store.store(legacy, password("written"), null);
        assertEquals(Map.of("key", "written", "sibling", "first sibling"),
                vault.logical().read("upgrade-v2/version-selection").getData());
        assertEquals("written", read(store, modern));
        assertEquals("first", read(store, legacy));
        store.remove(legacy, PasswordCredential.class, null, null);
        assertNull(store.retrieve(modern, PasswordCredential.class, null, null, null));
        assertEquals("first", read(store, legacy));
        assertEquals(Map.of("sibling", "first sibling"), vault.logical().read("upgrade-v2/version-selection").getData());
        VaultCredentialSource source = new VaultCredentialSource(new VaultConnector(container.getHttpHostAddress(),
                "myroot", null, new SslConfig(), true), "upgrade-v2/version-selection?version=1", "key");
        assertEquals("first", new String(source.getCredential(PasswordCredential.class, null, null)
                .getPassword(ClearPassword.class).getPassword()));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    @SuppressWarnings("deprecation")
    void testFinalObjectCredentialTextDoesNotChangeModernTraversalOrCache(int version) throws Exception {
        Vault vault = rawVault(version);
        String mount = "upgrade-v" + version;
        String rawPath = mount + "/opaque-objects";
        var object = Json.parse("""
                {"nested":{"credential":"leaf"},"nil":null,"number":123,"enabled":true,
                 "text":"a string","array":["value",null,2,true]}
                """).asObject();
        Map<String, Object> payload = Map.of("object", object, "object/with/slash", object, "sibling", "keep");
        for (String key : List.of("object", "object/with/slash")) {
            write(vault, rawPath, payload);
            String legacy = rawPath + "." + key;
            String modern = "@" + mount + "#opaque-objects?"
                    + (key.equals("object") ? "object" : "object%2Fwith%2Fslash");
            String nested = modern + "/nested/credential";
            String expected = vault.logical().read(rawPath).getData().get(key);
            HashicorpVaultCredentialStore store = store(version, true);
            assertNull(store.retrieve(modern, PasswordCredential.class, null, null, null));
            assertEquals(expected, read(store, legacy), "Preserve exact JSON, including types and null members");
            assertNull(store.retrieve(modern, PasswordCredential.class, null, null, null),
                    "Legacy object text must not leak through the shared scalar alias cache");
            assertEquals("leaf", read(store, nested));
            assertEquals(expected, read(store, legacy));
            assertNull(store(version, false).retrieve(modern, PasswordCredential.class, null, null, null));
            assertEquals("leaf", read(store(version, false), nested));
            if (version == 2) {
                VaultConnector connector = new VaultConnector(container.getHttpHostAddress(), "myroot", null,
                        new SslConfig(), true);
                for (String path : List.of(rawPath, rawPath + "?version=1")) {
                    var source = new VaultCredentialSource(connector, path, key);
                    assertEquals(expected, new String(source.getCredential(PasswordCredential.class, null, null)
                            .getPassword(ClearPassword.class).getPassword()));
                }
            }
            // Replacing or removing a legacy object must evict already cached modern children.
            store.store(legacy, password("replacement"), null);
            assertNull(store.retrieve(nested, PasswordCredential.class, null, null, null));
            assertEquals("replacement", read(store, modern));
            write(vault, rawPath, payload);
            store = store(version, true);
            assertEquals("leaf", read(store, nested));
            assertEquals(expected, read(store, legacy));
            store.remove(legacy, PasswordCredential.class, null, null);
            assertNull(store.retrieve(modern, PasswordCredential.class, null, null, null));
            assertNull(store.retrieve(nested, PasswordCredential.class, null, null, null));
            var remaining = vault.logical().read(rawPath).getDataObject();
            String other = key.equals("object") ? "object/with/slash" : "object";
            assertEquals(expected, remaining.get(other).toString());
            assertEquals("keep", remaining.getString("sibling", null));
        }
    }

    private static void assertUntouched(Vault vault, Map<String, Map<String, Object>> untouched) throws Exception {
        for (var entry : untouched.entrySet()) {
            assertEquals(entry.getValue(), vault.logical().read(entry.getKey()).getData(), entry.getKey());
        }
    }

    private Vault rawVault(int version) throws Exception {
        return Vault.create(new VaultConfig().address(container.getHttpHostAddress()).token("myroot")
                .engineVersion(version).build());
    }

    private static void write(Vault vault, String path, Map<String, Object> data) throws Exception {
        int status = vault.logical().write(path, data).getRestResponse().getStatus();
        assertTrue(status == 200 || status == 204, "Raw seed failed: HTTP " + status);
    }

    private HashicorpVaultCredentialStore store(int version, boolean legacy) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        store.initialize(Map.of("host-address", container.getHttpHostAddress(), "default-engine-type", "KVv" + version,
                        "default-mount-path", "upgrade-v" + version, "support-legacy-alias-format", String.valueOf(legacy)),
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
