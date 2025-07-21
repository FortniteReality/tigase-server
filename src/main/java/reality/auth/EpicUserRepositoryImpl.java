package reality.auth;

import tigase.db.*;
import tigase.xmpp.jid.BareJID;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EpicUserRepositoryImpl implements UserRepository {

    private static class UserData {
        final Map<String, String> properties = new ConcurrentHashMap<>();
    }

    private static final Map<BareJID, UserData> users = new ConcurrentHashMap<>();


    private static final EpicUserRepositoryImpl INSTANCE = new EpicUserRepositoryImpl();

    public static EpicUserRepositoryImpl getInstance() {
        return INSTANCE;
    }

    @Override
    public void addUser(BareJID jid) throws UserExistsException, TigaseDBException {
        UserData previous = users.putIfAbsent(jid, new UserData());
        if (previous != null) {
            throw new UserExistsException("User " + jid + " already exists.");
        }
    }

    @Override
    public void removeUser(BareJID jid) throws UserNotFoundException, TigaseDBException {
        if (users.remove(jid) == null) {
            throw new UserNotFoundException("User " + jid + " not found.");
        }
    }

    @Override
    public boolean userExists(BareJID jid) {
        return users.containsKey(jid);
    }

    @Override
    public void setData(BareJID user, String key, String value) throws UserNotFoundException, TigaseDBException {
        UserData userData = users.get(user);
        if (userData == null) {
            throw new UserNotFoundException("User " + user + " not found.");
        }
        if (value == null) {
            userData.properties.remove(key);
        } else {
            userData.properties.put(key, value);
        }
    }

    @Override
    public String getData(BareJID user, String key) throws UserNotFoundException, TigaseDBException {
        UserData userData = users.get(user);
        if (userData == null) {
            throw new UserNotFoundException("User " + user + " not found.");
        }
        return userData.properties.get(key);
    }

    @Override
    public String getData(BareJID user, String subnode, String key) throws UserNotFoundException, TigaseDBException {
        return getData(user, key);
    }

    @Override
    public void setData(BareJID user, String subnode, String key, String value) throws UserNotFoundException, TigaseDBException {
        setData(user, key, value);
    }

    @Override
    public List<BareJID> getUsers() throws TigaseDBException {
        return new ArrayList<>(users.keySet());
    }

    @Override
    public long getUsersCount() {
        return users.size();
    }

    @Override
    public long getUsersCount(String domain) {
        if (domain == null) return 0;
        return users.keySet().stream().filter(jid -> domain.equals(jid.getDomain())).count();
    }

    @Override
    public String getResourceUri() {
        return "epic-user-repo://in-memory";
    }

    // These methods are for more advanced features not needed by the auth class so they're unsupported.

    @Override
    public void addDataList(BareJID user, String subnode, String key, String[] list) throws TigaseDBException {
        throw new UnsupportedOperationException("This repository does not support data lists.");
    }
    @Override
    public String[] getDataList(BareJID user, String subnode, String key) throws TigaseDBException {
        throw new UnsupportedOperationException("This repository does not support data lists.");
    }
    @Override
    public void setDataList(BareJID user, String subnode, String key, String[] list) throws TigaseDBException {
        throw new UnsupportedOperationException("This repository does not support data lists.");
    }
    @Override
    public String getData(BareJID user, String subnode, String key, String def) throws UserNotFoundException, TigaseDBException {
        String value = getData(user, subnode, key);
        return value != null ? value : def;
    }
    @Override
    public String[] getKeys(BareJID user, String subnode) throws UserNotFoundException, TigaseDBException {
        UserData userData = users.get(user);
        if (userData == null) throw new UserNotFoundException("User " + user + " not found.");
        return userData.properties.keySet().toArray(new String[0]);
    }
    @Override
    public String[] getKeys(BareJID user) throws UserNotFoundException, TigaseDBException {
        return getKeys(user, null);
    }
    @Override
    public void removeData(BareJID user, String subnode, String key) throws UserNotFoundException, TigaseDBException {
        setData(user, subnode, key, null);
    }
    @Override
    public void removeData(BareJID user, String key) throws UserNotFoundException, TigaseDBException {
        setData(user, null, key, null);
    }

    @Override public String[] getSubnodes(BareJID user, String subnode) { return new String[0]; }
    @Override public String[] getSubnodes(BareJID user) { return new String[0]; }
    @Override public long getUserUID(BareJID user) { return 0; }
    @Override public void removeSubnode(BareJID user, String subnode) {}
}