/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.StringTokenizer;

import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Represents a parsed Vault path consisting of engine type, mount path, and secret path.
 *
 * <p>This class serves as the base for {@link VaultAlias} and can be used independently
 * for operations that don't require a specific key path (e.g., listing secrets).
 *
 * <p>Format: {@code [engine=TYPE][@mount-path]#secret-path}
 *
 * <p>Components:
 * <ul>
 *   <li>{@code engine=TYPE} - Optional engine type specification (e.g., {@code engine=KVv1}, {@code engine=KVv2})</li>
 *   <li>{@code @mount-path} - Optional mount path (e.g., {@code @secret}, {@code @team/backend})</li>
 *   <li>{@code #secret-path} - Secret path (e.g., {@code #myapp/database})</li>
 * </ul>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code #myapp/database} - Simple path with defaults</li>
 *   <li>{@code engine=KVv1@secret-v1#myapp} - Explicit engine and mount</li>
 *   <li>{@code @custom-mount#my.app.config} - Custom mount with dots in path</li>
 *   <li>{@code secret/myapp} - Legacy format (when supported)</li>
 * </ul>
 */
class VaultPath {

    private final String engineType;
    private final String mountPath;
    private final String secretPath;

    /**
     * Protected constructor - use factory methods to create instances.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     */
    protected VaultPath(String engineType, String mountPath, String secretPath) {
        this.engineType = engineType;
        this.mountPath = mountPath;
        this.secretPath = secretPath;
    }

    /**
     * Create a VaultPath directly from components without parsing.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path (can be empty for root listing)
     * @return a new VaultPath instance
     * @throws CredentialStoreException if the engine type is invalid or any required component is null
     */
    static VaultPath create(String engineType, String mountPath, String secretPath) throws CredentialStoreException {
        // Validate required parameters
        if (engineType == null || engineType.isEmpty()) {
            throw ROOT_LOGGER.engineTypeCannotBeEmpty("direct creation");
        }
        if (mountPath == null || mountPath.isEmpty()) {
            throw ROOT_LOGGER.mountPathCannotBeEmpty("direct creation");
        }
        if (secretPath == null) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty("direct creation");
        }

        // Validate engine type
        if (!engineType.equals(VaultConstants.ENGINE_TYPE_KV_V1) && !engineType.equals(VaultConstants.ENGINE_TYPE_KV_V2)) {
            throw ROOT_LOGGER.invalidEngineType(engineType);
        }

        return new VaultPath(engineType, mountPath, secretPath);
    }

    /**
     * Parse a vault path or alias string with specified defaults and legacy format support.
     *
     * <p>This method parses paths in the format: {@code [engine=TYPE][@mount-path]#secret-path[?key-path]}
     * or legacy format {@code mount/secret-path[.key]} (when supported).
     *
     * @param <T> the type of VaultPath to return (VaultPath or VaultAlias)
     * @param input the path or alias string to parse
     * @param defaultEngineType the default engine type to use if not specified
     * @param defaultMountPath the default mount path to use if not specified
     * @param supportLegacyFormat whether to support legacy format
     * @param requireKey whether a key path is required (true for VaultAlias, false for VaultPath)
     * @param resultClass the class of the result type
     * @return the parsed VaultPath or VaultAlias
     * @throws CredentialStoreException if the format is invalid
     */
    static <T extends VaultPath> T parse(String input, String defaultEngineType, String defaultMountPath,
                                          boolean supportLegacyFormat, boolean requireKey, Class<T> resultClass)
            throws CredentialStoreException {
        if (input == null || input.isEmpty()) {
            throw ROOT_LOGGER.aliasCannotBeNullOrEmpty();
        }

        ROOT_LOGGER.debugf("Parsing vault %s: %s", requireKey ? "alias" : "path", input);

        // Explicit prefixes reserve the new grammar. With compatibility enabled a dot alias wins
        // over markers inside its literal key (including '?'), as it did in 1.0.1.Final.
        int questionPos = input.indexOf('?');
        int hashPos = input.indexOf('#');
        boolean explicitFormat = input.startsWith("#") || ((input.startsWith("@") || input.startsWith("engine="))
                && hashPos >= 0 && questionPos > hashPos);
        // A mount can itself start with '@' or 'engine='. Reserve the complete modern header,
        // rather than mistaking such a Final mount-qualified alias for an incomplete modern alias.
        int end = input.length();
        // String.split("\\."), used by Final, discarded trailing empty components.
        while (end > 0 && input.charAt(end - 1) == '.') {
            end--;
        }
        int lastDot = input.lastIndexOf('.', end - 1);
        boolean legacyAlias = requireKey && !explicitFormat && lastDot >= 0
                && (supportLegacyFormat || questionPos == -1);
        if (legacyAlias) {
            VaultAlias alias = legacyAlias(input.substring(0, lastDot), input.substring(lastDot + 1, end),
                    defaultEngineType, defaultMountPath);
            String replacement = "@" + encodePath(alias.getMountPath())
                    + toAlias(alias.getSecretPath(), alias.getKeyPath());
            if (!supportLegacyFormat) {
                throw ROOT_LOGGER.legacyAliasFormatNotSupported(input, replacement);
            }
            if (alias.getLegacyQuery() == null) {
                ROOT_LOGGER.legacyAliasFormatDeprecated(input, replacement);
            } else {
                ROOT_LOGGER.legacyAliasWithQueryDeprecated(input);
            }
            return resultClass.cast(alias);
        }

        String path = input;
        String keyPath = null;
        if (questionPos != -1) {
            path = input.substring(0, questionPos);
            keyPath = input.substring(questionPos + 1);
        } else if (requireKey) {
            throw ROOT_LOGGER.missingQuestionDelimiterBeforeKeyPath(input);
        }
        return parsePathPart(path, keyPath, defaultEngineType, defaultMountPath, supportLegacyFormat, requireKey,
                resultClass);
    }

    /**
     * Convert the full wire path used by Final into decoded components for the current connector.
     * Split the mount before decoding, preserve literal plus signs, and keep the key verbatim.
     */
    static VaultAlias legacyAlias(String path, String key, String engineType, String defaultMountPath)
            throws CredentialStoreException {
        // Both driver generations tokenize the raw full path before URI handling. Normalize here
        // too so cache identity/eviction agrees with the route, including repeated leading slashes.
        boolean trailingSlash = path.endsWith("/");
        StringTokenizer tokens = new StringTokenizer(path, "/");
        StringBuilder normalized = new StringBuilder();
        while (tokens.hasMoreTokens()) {
            if (normalized.length() > 0) {
                normalized.append('/');
            }
            normalized.append(tokens.nextToken());
        }
        if (trailingSlash) {
            normalized.append('/');
        }
        path = normalized.toString();

        // Fragments never reach Vault, but queries can select a KV v2 secret version. Split
        // before percent decoding: encoded %3F and %23 are literal characters in a secret name.
        int fragment = path.indexOf('#');
        if (fragment >= 0) {
            path = path.substring(0, fragment);
        }
        String query = null;
        int question = path.indexOf('?');
        if (question >= 0) {
            query = path.substring(question + 1);
            path = path.substring(0, question);
        }
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        String mount = defaultMountPath;
        int slash = path.indexOf('/');
        if (slash >= 0) {
            mount = path.substring(0, slash);
            path = path.substring(slash + 1);
        }
        return VaultAlias.createWithLiteralKey(engineType, legacyPathDecode(mount), legacyPathDecode(path), key)
                .withLegacyQuery(query);
    }

    private static String legacyPathDecode(String path) {
        // URLDecoder uses form semantics; '+' in an HTTP path was a literal plus in Final.
        return urlDecode(path.replace("+", "%2B"));
    }

    /**
     * Internal method to parse the path components and optionally create VaultAlias with key.
     */
    @SuppressWarnings("unchecked")
    private static <T extends VaultPath> T parsePathPart(String path, String keyPath, String defaultEngineType,
                                                          String defaultMountPath, boolean supportLegacyFormat,
                                                          boolean requireKey, Class<T> resultClass)
            throws CredentialStoreException {
        if (path == null || path.isEmpty()) {
            throw ROOT_LOGGER.aliasCannotBeNullOrEmpty();
        }

        ROOT_LOGGER.debugf("Parsing vault path: %s", path);

        // Use local variables to collect parsed values
        String engineType = defaultEngineType;
        String mountPath = defaultMountPath;
        String secretPath;

        // Use index-based parsing to reduce GC pressure
        int pos = 0;
        final int length = path.length();

        // 1. Extract engine type (optional, starts with "engine=")
        if (path.startsWith("engine=")) {
            pos = 7; // Skip "engine="
            int nextDelim = findNextDelimiter(path, pos, '@', '#');
            if (nextDelim == -1) {
                throw ROOT_LOGGER.invalidEngineSpecificationMissingDelimiter(path);
            }
            engineType = path.substring(pos, nextDelim);
            if (engineType.isEmpty()) {
                throw ROOT_LOGGER.engineTypeCannotBeEmpty(path);
            }
            pos = nextDelim;
        }

        // 2. Extract mount path (optional, starts with @)
        if (pos < length && path.charAt(pos) == '@') {
            pos++; // Skip @
            int hashPos = path.indexOf('#', pos);
            if (hashPos == -1) {
                throw ROOT_LOGGER.missingHashDelimiterAfterMountPath(path);
            }
            mountPath = path.substring(pos, hashPos);
            if (mountPath.isEmpty()) {
                throw ROOT_LOGGER.mountPathCannotBeEmpty(path);
            }
            pos = hashPos;
        }

        // 3. Extract secret path
        // The # is required only after @ mount path, otherwise it's optional
        if (pos < length && path.charAt(pos) == '#') {
            pos++; // Skip # if present
        }

        // Extract remaining path
        String remainingPath = path.substring(pos);

        // Special case: "/" and "" are root paths (equivalent to "#" or "#/")
        if (remainingPath.equals("/") || remainingPath.isEmpty()) {
            secretPath = "";  // Root of default mount
        } else {
            // Check if this might be legacy format (contains / but no new format indicators)
            boolean hasNewFormatIndicators = path.contains("@") || path.contains("#") || path.startsWith("engine=");

            if (!hasNewFormatIndicators && remainingPath.contains("/") && supportLegacyFormat) {
                // Legacy format enabled - parse as mount/secretpath
                int firstSlash = remainingPath.indexOf('/');
                mountPath = remainingPath.substring(0, firstSlash);
                secretPath = remainingPath.substring(firstSlash + 1);
                ROOT_LOGGER.debugf("Parsed as legacy format: mount=%s, secret=%s", mountPath, secretPath);
            } else {
                // New format - use remaining as secret path (slashes are allowed)
                secretPath = remainingPath;
            }

            // 4. Handle empty secret path or trailing slash (root listing)
            if (secretPath.isEmpty() || secretPath.equals("/")) {
                secretPath = "";  // Normalize to empty for root
            }
        }

        // Validate secret path is not empty when parsing aliases (requireKey=true)
        if (requireKey && secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty(path);
        }

        // 5. URL-decode each segment separately
        // CRITICAL: Decode AFTER splitting to avoid double-encoding issues
        engineType = urlDecode(engineType);
        mountPath = urlDecode(mountPath);
        secretPath = urlDecode(secretPath);

        // 6. Validate engine type after URL decoding
        if (!engineType.equals(VaultConstants.ENGINE_TYPE_KV_V1) && !engineType.equals(VaultConstants.ENGINE_TYPE_KV_V2)) {
            throw ROOT_LOGGER.invalidEngineType(engineType);
        }

        // Validate and decode key path if present
        List<String> keyPathSegments = null;
        if (keyPath != null) {
            if (keyPath.isEmpty()) {
                throw ROOT_LOGGER.keyPathCannotBeEmpty(path + "?" + keyPath);
            }
            // New format: split on the raw (still encoded) key path so that an encoded %2F stays inside a
            // segment as a literal slash while an unencoded / separates nested segments.
            String[] rawSegments = keyPath.split("/", -1);
            if (rawSegments.length > 1) {
                for (String rawSegment : rawSegments) {
                    if (rawSegment.isEmpty()) {
                        throw ROOT_LOGGER.keyPathContainsEmptySegment(urlDecode(keyPath));
                    }
                }
            }
            keyPathSegments = new ArrayList<>(rawSegments.length);
            for (String rawSegment : rawSegments) {
                keyPathSegments.add(urlDecode(rawSegment));
            }
        } else if (requireKey) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty(path);
        }

        ROOT_LOGGER.debugf("Parsed vault %s: engine=%s, mount=%s, secret=%s%s",
                          requireKey ? "alias" : "path", engineType, mountPath, secretPath,
                          keyPathSegments != null ? ", key=" + keyPathSegments : "");

        // Create appropriate instance based on whether key is present
        if (keyPathSegments != null) {
            // Return VaultAlias
            return (T) new VaultAlias(engineType, mountPath, secretPath, keyPathSegments);
        } else {
            // Return VaultPath
            return (T) new VaultPath(engineType, mountPath, secretPath);
        }
    }

    /**
     * Parse a vault path string with specified defaults and legacy format support.
     *
     * <p>This method parses paths in the format: {@code [engine=TYPE][@mount-path]#secret-path}
     * or legacy format {@code mount/secret-path} (when supported).
     *
     * @param path the path string to parse
     * @param defaultEngineType the default engine type to use if not specified
     * @param defaultMountPath the default mount path to use if not specified
     * @param supportLegacyFormat whether to support legacy {@code mount/secret} format
     * @return the parsed VaultPath
     * @throws CredentialStoreException if the path format is invalid
     */
    static VaultPath parse(String path, String defaultEngineType, String defaultMountPath, boolean supportLegacyFormat)
            throws CredentialStoreException {
        return parse(path, defaultEngineType, defaultMountPath, supportLegacyFormat, false, VaultPath.class);
    }

    /**
     * Find the position of the next delimiter character in the string.
     *
     * @param s the string to search
     * @param start the starting position
     * @param delims the delimiter characters to search for
     * @return the position of the first delimiter found, or -1 if none found
     */
    protected static int findNextDelimiter(String s, int start, char... delims) {
        int minPos = -1;
        for (char delim : delims) {
            int pos = s.indexOf(delim, start);
            if (pos != -1 && (minPos == -1 || pos < minPos)) {
                minPos = pos;
            }
        }
        return minPos;
    }

    /**
     * URL-encode a single name (a key, or one path segment) so that {@link #urlDecode(String)} gives back
     * exactly the same string. Spaces become {@code %20} (never {@code +}), and every character that is
     * meaningful in an alias, such as {@code / ? # @ % +}, is percent-encoded.
     *
     * @param s the decoded name
     * @return the encoded name
     */
    static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * URL-encode a path, encoding each {@code /}-separated segment but keeping the {@code /} separators.
     *
     * @param path the decoded path
     * @return the encoded path, which parses back to {@code path}
     */
    static String encodePath(String path) {
        String[] segments = path.split("/", -1);
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                encoded.append('/');
            }
            encoded.append(urlEncode(segments[i]));
        }
        return encoded.toString();
    }

    /**
     * Build the alias string for a key in a secret, in the form that {@link VaultAlias#parse(String)} reads back
     * as the same secret path and the same key: {@code #secret-path?key}. Slashes in the secret path are
     * separators, but a slash in the key is part of its name and so is encoded as {@code %2F}.
     *
     * @param secretPath the decoded secret path
     * @param key the decoded key (field) name
     * @return the alias
     */
    static String toAlias(String secretPath, String key) {
        return toAlias(secretPath, List.of(key));
    }

    /**
     * Build the alias string for a value in a secret, where the value may be inside nested JSON objects:
     * {@code #secret-path?segment/segment}. Each key segment is encoded on its own, so a slash that is part of a
     * segment's name is {@code %2F} and only the slashes between segments are traversal.
     *
     * @param secretPath the decoded secret path
     * @param keySegments the decoded key path segments, outermost first
     * @return the alias
     */
    static String toAlias(String secretPath, List<String> keySegments) {
        StringBuilder alias = new StringBuilder("#").append(encodePath(secretPath)).append('?');
        for (int i = 0; i < keySegments.size(); i++) {
            if (i > 0) {
                alias.append('/');
            }
            alias.append(urlEncode(keySegments.get(i)));
        }
        return alias.toString();
    }

    /**
     * URL-decode a string using UTF-8 encoding.
     *
     * @param s the string to decode
     * @return the decoded string, or the original string if decoding fails
     */
    protected static String urlDecode(String s) {
        if (s == null) {
            return null;
        }
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 should always be supported, but if not, return as-is
            return s;
        } catch (IllegalArgumentException e) {
            // Invalid URL encoding - return as-is
            return s;
        }
    }

    /**
     * Get the engine type (KVv1 or KVv2).
     *
     * @return the engine type
     */
    public String getEngineType() {
        return engineType;
    }

    /**
     * Get the mount path.
     *
     * @return the mount path
     */
    public String getMountPath() {
        return mountPath;
    }

    /**
     * Get the secret path.
     *
     * @return the secret path (may be empty for root listing)
     */
    public String getSecretPath() {
        return secretPath;
    }

    @Override
    public String toString() {
        return "VaultPath{" +
               "engineType='" + engineType + '\'' +
               ", mountPath='" + mountPath + '\'' +
               ", secretPath='" + secretPath + '\'' +
               '}';
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        VaultPath vaultPath = (VaultPath) o;
        return Objects.equals(engineType, vaultPath.engineType) && Objects.equals(mountPath, vaultPath.mountPath) && Objects.equals(secretPath, vaultPath.secretPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(engineType, mountPath, secretPath);
    }
}
