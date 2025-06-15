package reality.auth;

import tigase.db.TigaseDBException;
import tigase.db.UserExistsException;
import tigase.db.UserNotFoundException;
import tigase.db.UserRepository;
import tigase.xmpp.jid.BareJID;

import java.util.List;

public class EpicGamesUserRepo implements UserRepository {
    @Override
    public void addDataList(BareJID user, String subnode, String key, String[] list) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void addUser(BareJID user) throws UserExistsException, TigaseDBException {

    }

    @Override
    public String getData(BareJID user, String subnode, String key, String def) throws UserNotFoundException, TigaseDBException {
        return "";
    }

    @Override
    public String getData(BareJID user, String subnode, String key) throws UserNotFoundException, TigaseDBException {
        return "";
    }

    @Override
    public String getData(BareJID user, String key) throws UserNotFoundException, TigaseDBException {
        return "";
    }

    @Override
    public String[] getDataList(BareJID user, String subnode, String key) throws UserNotFoundException, TigaseDBException {
        return new String[0];
    }

    @Override
    public String[] getKeys(BareJID user, String subnode) throws UserNotFoundException, TigaseDBException {
        return new String[0];
    }

    @Override
    public String[] getKeys(BareJID user) throws UserNotFoundException, TigaseDBException {
        return new String[0];
    }

    @Override
    public String getResourceUri() {
        return "";
    }

    @Override
    public String[] getSubnodes(BareJID user, String subnode) throws UserNotFoundException, TigaseDBException {
        return new String[0];
    }

    @Override
    public String[] getSubnodes(BareJID user) throws UserNotFoundException, TigaseDBException {
        return new String[0];
    }

    @Override
    public long getUserUID(BareJID user) throws TigaseDBException {
        return 0;
    }

    @Override
    public List<BareJID> getUsers() throws TigaseDBException {
        return List.of();
    }

    @Override
    public long getUsersCount() {
        return 0;
    }

    @Override
    public long getUsersCount(String domain) {
        return 0;
    }

    @Override
    public void removeData(BareJID user, String subnode, String key) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void removeData(BareJID user, String key) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void removeSubnode(BareJID user, String subnode) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void removeUser(BareJID user) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void setData(BareJID user, String subnode, String key, String value) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void setData(BareJID user, String key, String value) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public void setDataList(BareJID user, String subnode, String key, String[] list) throws UserNotFoundException, TigaseDBException {

    }

    @Override
    public boolean userExists(BareJID user) {
        return true;
    }
}
