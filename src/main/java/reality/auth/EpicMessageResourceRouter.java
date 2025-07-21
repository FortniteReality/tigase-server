package reality.auth;

import tigase.db.NonAuthUserRepository;
import tigase.kernel.beans.Inject;
import tigase.server.Packet;
import tigase.server.xmppsession.SessionManager;
import tigase.xml.Element;
import tigase.xmpp.*;
import tigase.xmpp.jid.BareJID;
import tigase.xmpp.jid.JID;

import java.util.Map;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EpicMessageResourceRouter extends XMPPProcessor implements XMPPProcessorIfc {

    private static final Logger log = Logger.getLogger(EpicMessageResourceRouter.class.getName());
    private static final String BIND_XMLNS = "urn:ietf:params:xml:ns:xmpp-bind";
    private static final String IQ_AUTH_XMLNS = "jabber:iq:auth"; // The namespace for legacy auth
    private final EpicUserRepositoryImpl repo = EpicUserRepositoryImpl.getInstance();

    @Inject
    private SessionManager sessionManager;

    @Override
    public String id() {
        return "epic-bare-jid-router";
    }

    @Override
    public Element[] supStreamFeatures(XMPPResourceConnection session) {
        return null;
    }

    @Override
    public Authorization canHandle(Packet packet, XMPPResourceConnection session) {
        return Authorization.AUTHORIZED;
    }

    @Override
    public void process(Packet packet, XMPPResourceConnection conn, NonAuthUserRepository userRepo,
                        Queue<Packet> results, Map<String, Object> settings) throws XMPPException {

        if (sessionManager == null) {
            log.severe("SessionManager was not injected. EpicMessageResourceRouter cannot function.");
            results.offer(packet);
            return;
        }

        trackResource(packet);

        String elemName = packet.getElemName();
        StanzaType type = packet.getType();
        JID toJid = packet.getStanzaTo();

        if (!packet.wasProcessed() && toJid != null && toJid.getResource() == null) {

            boolean isRoutableStanza = "message".equals(elemName) || "presence".equals(elemName);
            boolean isSpecialPresence = "presence".equals(elemName) &&
                    (StanzaType.subscribe.equals(type) || StanzaType.unsubscribe.equals(type) ||
                            StanzaType.subscribed.equals(type) || StanzaType.unsubscribed.equals(type) ||
                            StanzaType.probe.equals(type));

            if (isRoutableStanza && !isSpecialPresence) {
                BareJID bare = toJid.getBareJID();
                try {
                    String resource = repo.getData(bare, "activeResource");
                    if (resource != null && !resource.isEmpty()) {
                        JID fullJid = JID.jidInstance(bare, resource);
                        Packet clonedPacket = packet.copyElementOnly();
                        clonedPacket.initVars(packet.getStanzaFrom(), fullJid);
                        results.offer(clonedPacket);
                        packet.processedBy(id());
                    }
                } catch (Exception e) {
                    log.log(Level.WARNING, "Exception during rerouting for " + bare, e);
                }
            }
        }

        if (!packet.wasProcessed()) {
            results.offer(packet);
        }
    }

    private void trackResource(Packet packet) {
        try {
            String elemName = packet.getElemName();
            StanzaType type = packet.getType();
            JID from = packet.getStanzaFrom();

            if ("iq".equals(elemName) && StanzaType.result.equals(type)) {
                Element bind = packet.getElement().getChild("bind", BIND_XMLNS);
                if (bind != null) {
                    Element jidEl = bind.getChild("jid");
                    if (jidEl != null && jidEl.getCData() != null) {
                        JID fullJid = JID.jidInstance(jidEl.getCData());
                        repo.setData(fullJid.getBareJID(), "activeResource", fullJid.getResource());
                        log.log(Level.INFO, "Tracked resource ''{0}'' for user {1} from BIND.", new Object[]{fullJid.getResource(), fullJid.getBareJID()});
                    }
                }

            } else if ("presence".equals(elemName) && (type == null || StanzaType.available.equals(type))) {
                if (from != null && from.getResource() != null) {
                    repo.setData(from.getBareJID(), "activeResource", from.getResource());
                }

            } else if ("iq".equals(elemName) && StanzaType.set.equals(type) && from != null) {
                Element query = packet.getElement().getChild("query", IQ_AUTH_XMLNS);
                if (query != null) {
                    Element resourceEl = query.getChild("resource");
                    if (resourceEl != null && resourceEl.getCData() != null) {
                        String resource = resourceEl.getCData();
                        if (!resource.isEmpty()) {
                            repo.setData(from.getBareJID(), "activeResource", resource);
                            log.log(Level.INFO, "Tracked resource ''{0}'' for user {1} from IQ-AUTH.", new Object[]{resource, from.getBareJID()});
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.log(Level.WARNING, "Exception during resource tracking.", e);
        }
    }
}