package reality.auth;

import tigase.annotations.TigaseDeprecated;
import tigase.server.AbstractMessageReceiver;
import tigase.server.Packet;
import tigase.xmpp.jid.BareJID;

@Deprecated(since = "8.5.0")
@TigaseDeprecated(note = "Incase we need it later, directly implemented into EpicMessageResourceRouter.", since = "8.5.0", removeIn = "9.0.0")
public class EpicPresenceResourceTracker extends AbstractMessageReceiver {

    private final EpicUserRepositoryImpl repo = new EpicUserRepositoryImpl();

    @Override
    public void processPacket(Packet packet) {
        if ("presence".equals(packet.getElemName())) {
            BareJID bareJid = packet.getStanzaFrom().getBareJID();
            String resource = packet.getStanzaFrom().getResource();

            try {
                if (resource != null && !resource.isEmpty()) {
                    repo.setData(bareJid, "activeResource", resource);
                }
            } catch (Exception e) {}
        }
    }
}