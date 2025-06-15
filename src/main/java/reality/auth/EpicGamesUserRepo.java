package reality.auth;

import tigase.db.*;
import tigase.xmpp.jid.BareJID;

public class EpicGamesUserRepo extends UserRepositoryPool {
    @Override
    public boolean userExists(BareJID user) {
        return true;
    }
}
