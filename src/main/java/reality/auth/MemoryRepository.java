package reality.auth;

import tigase.annotations.TigaseDeprecated;
import tigase.component.exceptions.RepositoryException;
import tigase.db.*;
import tigase.util.Base64;
import tigase.util.Version;
import tigase.xmpp.jid.BareJID;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory repository implementation that stores data in HashMaps
 * Completely user-independent version - ignores all user parameters
 * Stores data globally without any user association
 */
public class MemoryRepository implements Repository, DataSource, UserRepository, AuthRepository {

    // Global data storage: subnode -> key -> value
    private final Map<String, Map<String, String>> globalData = new ConcurrentHashMap<>();

    // Global list data storage: subnode -> key -> list of values
    private final Map<String, Map<String, String[]>> globalDataLists = new ConcurrentHashMap<>();

    private String secretKey = null;

    private String getSecretKey() {
        if (secretKey == null) {
            SecureRandom random = new SecureRandom();
            byte[] secret = new byte[32];
            random.nextBytes(secret);
            secretKey = Base64.encode(secret);
        }
        return secretKey;
    }

    @Override
    public void addDataList(BareJID user, String subnode, String key, String[] list) {
        globalDataLists.computeIfAbsent(subnode != null ? subnode : "", k -> new ConcurrentHashMap<>())
                .put(key, list != null ? list.clone() : new String[0]);
    }

    @Override
    public void addUser(BareJID user) {
        // No-op - completely user-independent
    }

    @Override
    public long getActiveUsersCountIn(Duration duration) {
        return 0; // Always 0 as no users are tracked
    }

    @Override
    public void addUser(BareJID user, String password) throws UserExistsException, TigaseDBException {
        // No-op for user creation, but set password if provided
        if (password != null) {
            setData(user, "password", password);
        }
    }

    @Override
    public String getData(BareJID user, String subnode, String key, String def) {
        if (key.equals("jwtSecretKey")) {
            return getSecretKey();
        }

        Map<String, String> subnodeMap = globalData.get(subnode != null ? subnode : "");
        if (subnodeMap == null) {
            return def != null ? def : "";
        }

        String value = subnodeMap.get(key);
        return value != null ? value : (def != null ? def : "");
    }

    @Override
    public String getData(BareJID user, String subnode, String key) {
        if (key.equals("jwtSecretKey")) {
            return getSecretKey();
        }

        return getData(user, subnode, key, "");
    }

    @Override
    public String getData(BareJID user, String key) {
        if (key.equals("jwtSecretKey")) {
            return getSecretKey();
        }

        return getData(user, "", key, "");
    }

    @Override
    public String[] getDataList(BareJID user, String subnode, String key) {
        Map<String, String[]> subnodeMap = globalDataLists.get(subnode != null ? subnode : "");
        if (subnodeMap == null) {
            return new String[0];
        }

        String[] list = subnodeMap.get(key);
        return list != null ? list.clone() : new String[0];
    }

    @Override
    public String[] getKeys(BareJID user, String subnode) {
        Map<String, String> subnodeMap = globalData.get(subnode != null ? subnode : "");
        if (subnodeMap == null) {
            return new String[0];
        }

        return subnodeMap.keySet().toArray(new String[0]);
    }

    @Override
    public String[] getKeys(BareJID user) {
        return getKeys(user, "");
    }

    @Override
    public Optional<Version> getSchemaVersion(String component) {
        return Optional.empty();
    }

    @Override
    public String getResourceUri() {
        return "memory://in-memory-repository";
    }

    @Override
    @Deprecated
    @TigaseDeprecated(since = "8.2.0", removeIn = "9.0.0", note = "Support for multi-level nodes will be removed")
    public String[] getSubnodes(BareJID user, String subnode) {
        return globalData.keySet().stream()
                .filter(key -> key.startsWith(subnode != null ? subnode : ""))
                .toArray(String[]::new);
    }

    @Override
    public String[] getSubnodes(BareJID user) {
        return getSubnodes(user, "");
    }

    @Override
    public long getUserUID(BareJID user) throws TigaseDBException {
        return user.hashCode(); // Simple UID implementation
    }

    @Override
    public List<BareJID> getUsers() {
        return new ArrayList<>(); // Always empty as no users are tracked
    }

    @Override
    public long getUsersCount() {
        return 0; // Always 0 as no users are tracked
    }

    @Override
    public long getUsersCount(String domain) {
        return 0; // Always 0 as no users are tracked
    }

    @Override
    public void initialize(String connStr) throws RepositoryException {
        // Nothing to initialize for in-memory storage
    }

    @Override
    @Deprecated
    public void initRepository(String string, Map<String, String> params) {
        // Nothing to initialize for in-memory storage
    }

    @Override
    public void loggedIn(BareJID jid) throws TigaseDBException {
        // No-op - user-independent
    }

    @Override
    public void logout(BareJID user) throws UserNotFoundException, TigaseDBException {
        // No-op - user-independent
    }

    @Override
    public boolean otherAuth(Map<String, Object> authProps)
            throws UserNotFoundException, TigaseDBException, AuthorizationException {
        return false; // Override in your custom auth implementation
    }

    @Override
    public void queryAuth(Map<String, Object> authProps) {
        // Override in your custom auth implementation
    }

    @Override
    public void removeData(BareJID user, String subnode, String key) {
        Map<String, String> subnodeMap = globalData.get(subnode != null ? subnode : "");
        if (subnodeMap != null) {
            subnodeMap.remove(key);
        }

        // Also remove from data lists
        Map<String, String[]> subnodeListMap = globalDataLists.get(subnode != null ? subnode : "");
        if (subnodeListMap != null) {
            subnodeListMap.remove(key);
        }
    }

    @Override
    public void removeData(BareJID user, String key) {
        removeData(user, "", key);
    }

    @Override
    public void removeSubnode(BareJID user, String subnode) {
        globalData.remove(subnode != null ? subnode : "");
        globalDataLists.remove(subnode != null ? subnode : "");
    }

    @Override
    public void removeUser(BareJID user) {
        // No-op - completely user-independent
    }

    @Override
    public void setData(BareJID user, String subnode, String key, String value) {
        globalData.computeIfAbsent(subnode != null ? subnode : "", k -> new ConcurrentHashMap<>())
                .put(key, value != null ? value : "");
    }

    @Override
    public void setData(BareJID user, String key, String value) {
        setData(user, "", key, value);
    }

    @Override
    public void setDataList(BareJID user, String subnode, String key, String[] list) {
        globalDataLists.computeIfAbsent(subnode != null ? subnode : "", k -> new ConcurrentHashMap<>())
                .put(key, list != null ? list.clone() : new String[0]);
    }

    @Override
    public void updatePassword(BareJID user, String password) throws UserNotFoundException, TigaseDBException {
        // Set password data globally
        setData(user, "password", password);
    }

    @Override
    public boolean userExists(BareJID user) {
        return true; // All users exist dynamically
    }

    @Override
    public String getPassword(BareJID user) throws UserNotFoundException, TigaseDBException {
        // Get password from global data
        return getData(user, "password");
    }

    @Override
    public boolean isUserDisabled(BareJID user) throws UserNotFoundException, TigaseDBException {
        return false; // Users are never disabled
    }

    @Override
    public void setUserDisabled(BareJID user, Boolean value) throws UserNotFoundException, TigaseDBException {
        // No-op - user-independent
    }

    @Override
    public void setAccountStatus(BareJID user, AccountStatus status) throws TigaseDBException {
        // No-op - user-independent
    }

    @Override
    public AccountStatus getAccountStatus(BareJID user) throws TigaseDBException {
        return AccountStatus.active; // Always active
    }
}