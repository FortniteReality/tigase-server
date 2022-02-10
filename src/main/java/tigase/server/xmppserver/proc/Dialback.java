/*
 * Tigase XMPP Server - The instant messaging server
 * Copyright (C) 2004 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 */
package tigase.server.xmppserver.proc;

import tigase.cert.CertCheckResult;
import tigase.kernel.beans.Bean;
import tigase.kernel.beans.config.ConfigField;
import tigase.net.ConnectionType;
import tigase.server.Packet;
import tigase.server.xmppserver.*;
import tigase.stats.StatisticsList;
import tigase.util.Algorithms;
import tigase.xml.Element;
import tigase.xmpp.StanzaType;
import tigase.xmpp.jid.JID;

import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created: Dec 9, 2010 2:00:52 PM
 *
 * @author <a href="mailto:artur.hefczyc@tigase.org">Artur Hefczyc</a>
 */
@Bean(name = "dialback", parent = S2SConnectionManager.class, active = true)
public class Dialback
		extends AuthenticationProcessor {

	private static final String METHOD_NAME = "DIALBACK";
	private static final Logger log = Logger.getLogger(Dialback.class.getName());
	private static final Element features_required = new Element("dialback", new Element[]{new Element("required")},
																 new String[]{"xmlns"},
																 new String[]{"urn:xmpp:features:dialback"});
	private static final Element features = new Element("dialback", new String[]{"xmlns"},
														new String[]{"urn:xmpp:features:dialback"});
	private static final String REQUESTED_RESULT_DOMAINS_KEY = "requested-result-domains-key";
	// Ejabberd does not request dialback after TLS (at least some versions don't)
	@ConfigField(desc = "Workaround for TLS dialback issue in Ejabberd", alias = "ejabberd-bug-workaround")
	private boolean ejabberd_bug_workaround_active = true;

	public Dialback() {
		super();
	}

	@Override
	public String getMethodName() {
		return METHOD_NAME;
	}

	@Override
	public int order() {
		return Order.Dialback.ordinal();
	}

	@Override
	public boolean process(Packet p, S2SIOService serv, Queue<Packet> results) {
		// If this is a dialback packet, process it accordingly
		if (p.getXMLNS() == XMLNS_DB_VAL) {
			if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "Processing dialback packet: {1} [{0}]", new Object[]{serv, p});
			}
			processDialback(p, serv);

			return true;
		}

		if (authenticatorSelectorManager.isAllowed(p, serv, this, results)) {
			if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "Initializing dialback, packet: {1} [{0}]", new Object[]{serv, p});
			}
			initDialback(serv, serv.getSessionId());
			return true;
		}

		return false;
	}

	@Override
	public void streamFeatures(S2SIOService serv, List<Element> results) {
		if (!serv.isAuthenticated()) {
			results.add(features);
			authenticatorSelectorManager.getAuthenticationProcessors(serv).add(this);
		}
	}

	@Override
	public String streamOpened(S2SIOService serv, Map<String, String> attribs) {
		if (attribs.containsKey("version")) {

			// Let's wait for stream features
			return null;
		}
		switch (serv.connectionType()) {
			case connect:
				if (log.isLoggable(Level.FINEST)) {
					log.log(Level.FINEST, "Initializing dialback after stream opened: {1} [{0}]",
							new Object[]{serv, attribs.get("id")});
				}
				initDialback(serv, attribs.get("id"));
				break;

			default:

				// Ignore
		}

		return null;
	}

	@Override
	public void restartAuth(Packet packet, S2SIOService serv, Queue<Packet> results) {
		initDialback(serv, serv.getSessionId());
	}

	@Override
	public boolean canHandle(Packet p, S2SIOService serv, Queue<Packet> results) {
		CID cid = (CID) serv.getSessionData().get("cid");
		boolean skipTLS = (cid != null) && skipTLSForHost(cid.getRemoteHost());

		if (p.isElement(FEATURES_EL, FEATURES_NS) && p.getElement().getChildren() != null &&
				!p.getElement().getChildren().isEmpty()) {
			if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "Stream features received packet: {1} [{0}]", new Object[]{serv, p});
			}

			CertCheckResult certCheckResult = (CertCheckResult) serv.getSessionData()
					.get(S2SIOService.CERT_CHECK_RESULT);

			if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "TLS Certificate check: {1}, packet: {2} [{0}]",
						new Object[]{serv, certCheckResult, p});
			}

			// If TLS is not yet started (announced in stream features) then it is not
			// the right time for dialback yet
			// Some servers send starttls in stream features, even if TLS is already
			// initialized....
			if (p.isXMLNSStaticStr(FEATURES_STARTTLS_PATH, START_TLS_NS) && (certCheckResult == null) && !skipTLS) {
				if (log.isLoggable(Level.FINEST)) {
					log.log(Level.FINEST, "Waiting for starttls, packet: {1} [{0}]", new Object[]{serv, p});
				}

				return false;
			}

			// If TLS has been started and it is a trusted peer, we do not need
			// dialback here but... sometimes the remote server may request dialback anyway,
			// especially if they do not trust us.
			if ((certCheckResult == CertCheckResult.trusted) &&
					!(p.isXMLNSStaticStr(FEATURES_DIALBACK_PATH, DIALBACK_NS))) {
				if (ejabberd_bug_workaround_active) {
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST,
								"Ejabberd bug workaround active, proceeding to dialback anyway, packet: {1} [{0}]",
								new Object[]{serv, p});
						return true;
					}
				} else {
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST, "TLS trusted peer, no dialback needed or requested, packet: {1} [{0}]",
								new Object[]{serv, p});
					}

					try {
						final CIDConnections cid_conns = handler.getCIDConnections(cid, true);
						authenticatorSelectorManager.authenticateConnection(serv, cid_conns, cid);
					} catch (NotLocalhostException ex) {

						// Should not happen....
						log.log(Level.INFO, "Incorrect local hostname, packet: {1} [{0}]", new Object[]{serv, p});
						authenticatorSelectorManager.authenticationFailed(p, serv, this, results);
					} catch (LocalhostException ex) {

						// Should not happen....
						log.log(Level.INFO, "Incorrect remote hostname name, packet: {1} [{0}]", new Object[]{serv, p});
						authenticatorSelectorManager.authenticationFailed(p, serv, this, results);
					}

					return false;
				}
			}

			// we need to check if TLS is required
			if (!skipTLS && cid != null && !serv.getSessionData().containsKey("TLS") &&
					handler.isTlsRequired(cid.getLocalHost())) {
				log.log(Level.FINER, "TLS is required for domain {1} but STARTTLS was not offered by {2} - policy-violation [{0}]",
						new Object[]{serv, cid.getLocalHost(), cid.getRemoteHost()});
//				authenticatorSelectorManager.authenticationFailed(p, serv, this, results);
				return false;
			}

			return true;

		}
		return false;
	}

	@Override
	public void getStatistics(String compName, StatisticsList list) {
		super.getStatistics(compName, list);
		authenticatorSelectorManager.getStatistics(compName, list);
	}

	/**
	 * Checks if result request for received domain was sent by service
	 */
	@SuppressWarnings("unchecked")
	protected boolean wasResultRequested(S2SIOService serv, String domain) {
		Set<String> requested = (Set<String>) serv.getSessionData().get(REQUESTED_RESULT_DOMAINS_KEY);

		return (requested != null) && requested.contains(domain);
	}

	/**
	 * Checks if verify request for received domain was sent by service
	 *
	 * @see CIDConnections#sendHandshakingOnly
	 */
	protected boolean wasVerifyRequested(S2SIOService serv, String domain) {
		String requested = (String) serv.getSessionData().get(S2SIOService.HANDSHAKING_DOMAIN_KEY);

		return (requested != null) && requested.contains(domain);
	}

	protected void initDialback(S2SIOService serv, String remote_id) {

		try {
			if (remote_id == null) {
				generateStreamError(false, "bad-request", serv);
				return;
			}
			CID cid = (CID) serv.getSessionData().get("cid");
			if (cid == null) {
				// can't process such request
				return;
			}

			String secret = handler.getSecretForDomain(cid.getLocalHost());
			String key = Algorithms.generateDialbackKey(cid.getLocalHost(), cid.getRemoteHost(), secret, remote_id);

			if (!serv.isHandshakingOnly()) {
				Element elem = new Element(DB_RESULT_EL_NAME, key, new String[]{XMLNS_DB_ATT},
										   new String[]{XMLNS_DB_VAL});

				addToResultRequested(serv, cid.getRemoteHost());
				serv.getS2SConnection()
						.addControlPacket(Packet.packetInstance(elem, JID.jidInstanceNS(cid.getLocalHost()),
																JID.jidInstanceNS(cid.getRemoteHost())));
			}
			serv.getS2SConnection().sendAllControlPackets();
		} catch (NotLocalhostException ex) {
			generateStreamError(false, "host-unknown", serv, ex);
		}
	}

	private void processDialback(Packet p, S2SIOService serv) {

		// Get the cid for which the connection has been created, the cid calculated
		// from the packet may be different though if the remote server tries to
		// multiplexing
		CID cid_main = (CID) serv.getSessionData().get("cid");
		CID cid_packet = new CID(p.getStanzaTo().getDomain(), p.getStanzaFrom().getDomain());

		if (log.isLoggable(Level.FINEST)) {
			log.log(Level.FINEST, "DIALBACK packet: {1}, CID_packet: {2} [{0}]", new Object[]{serv, p, cid_packet});
		}

		CIDConnections cid_conns = null;

		// Some servers (ejabberd) do not send from/to attributes in the stream:open
		// which
		// violates the spec, they seem not to care though, so here we handle the
		// case.
		if (cid_main == null) {

			// This actually can only happen for 'accept' connection type
			// what we did not get in stream open we can get from here
			cid_main = cid_packet;
			serv.getSessionData().put("cid", cid_main);

			// For debuging purposes only....
			serv.getSessionData().put("local-hostname", cid_main.getLocalHost());
			serv.getSessionData().put("remote-hostname", cid_main.getRemoteHost());
		}
		try {
			cid_conns = handler.getCIDConnections(cid_main, true);
		} catch (NotLocalhostException ex) {
			log.log(Level.FINER, "Incorrect local hostname: {1} [{0}]", new Object[]{serv, p});
			generateStreamError(false, "host-unknown", serv, ex);

			return;
		} catch (LocalhostException ex) {
			log.log(Level.FINER, "Incorrect remote hostname: {1} [{0}]", new Object[]{serv, p});
			generateStreamError(false, "invalid-from", serv, ex);

			return;
		}
		if (serv.connectionType() == ConnectionType.accept) {
			cid_conns.addIncoming(serv);
		}

		String remote_key = p.getElemCData();

		// Dummy dialback implementation for now....
		if ((p.getElemName() == RESULT_EL_NAME) || (p.getElemName() == DB_RESULT_EL_NAME)) {
			if (p.getType() == null) {
				CID cid = (CID) serv.getSessionData().get("cid");
				boolean skipTls = this.skipTLSForHost(cid.getRemoteHost());
				if (!skipTls && !serv.getSessionData().containsKey("TLS") &&
						handler.isTlsRequired(cid.getLocalHost())) {
					log.log(Level.FINER,
							"Rejecting S2S connection from {1} to {2} due to policy violation - STARTTLS is required [{0}]",
							new Object[]{serv, cid.getRemoteHost(), cid.getLocalHost()});
					handler.sendVerifyResult(DB_RESULT_EL_NAME, cid_main, cid_packet, false, null, serv.getSessionId(),
											 null, false, new Element("error", new Element[]{
									new Element("policy-violation", new String[]{"xmlns"},
												new String[]{"urn:ietf:params:xml:ns:xmpp-stanzas"})},
																	  new String[]{"type"}, new String[]{"cancel"}));
				} else {
					String conn_sessionId = serv.getSessionId();
					handler.sendVerifyResult(DB_VERIFY_EL_NAME, cid_main, cid_packet, null, conn_sessionId, null,
											 p.getElemCData(), true);
				}
			} else {
				if (p.getType() == StanzaType.valid) {
					if (wasResultRequested(serv, p.getStanzaFrom().toString())) {
						authenticatorSelectorManager.authenticateConnection(serv, cid_conns, cid_packet);

						// As per specification:
						// If the value of the 'type' attribute is "valid", then the connection between the domain pair
						// is considered verified and the Initiating Server can send any outbound stanzas
						// it has queued up for routing to the Receiving Server for the domain pair
						cid_conns.streamNegotiationCompleted(serv);
						serv.streamNegotiationCompleted();
					} else if (log.isLoggable(Level.FINE)) {
						log.log(Level.FINE, "Received result with type valid for {0} but it was not requested!",
								p.getStanzaFrom());
					}
				} else {
					if (log.isLoggable(Level.FINE)) {
						log.log(Level.FINE, "Invalid result for DB authentication: {0}, stopping connection: {1}",
								new Object[]{cid_packet, serv});
					}
					authenticatorSelectorManager.markConnectionAsFailed(getMethodName(), serv);
					serv.stop();
				}
			}
		}
		if ((p.getElemName() == VERIFY_EL_NAME) || (p.getElemName() == DB_VERIFY_EL_NAME)) {
			if (p.getType() == null) {
				boolean result;
				try {
					String secret = handler.getSecretForDomain(cid_packet.getLocalHost());
					String local_key = Algorithms.generateDialbackKey(cid_packet.getLocalHost(),
																	  cid_packet.getRemoteHost(), secret,
																	  p.getStanzaId());

					if (local_key == null) {
						if (log.isLoggable(Level.FINER)) {
							log.log(Level.FINER,
									"The key is not available for connection CID: {0}, " + "or the packet CID: {1} ",
									new Object[]{cid_main, cid_packet});
						}
					}
					result = local_key != null && local_key.equals(remote_key);
				} catch (NotLocalhostException ex) {
					if (log.isLoggable(Level.FINER)) {
						log.log(Level.FINER, "Could not retreive secret for " + cid_packet.getLocalHost(), ex);
					}
					result = false;
				}
				handler.sendVerifyResult(DB_VERIFY_EL_NAME, cid_main, cid_packet, result, p.getStanzaId(),
										 serv.getSessionId(), null, false);
			} else {
				if (wasVerifyRequested(serv, p.getStanzaFrom().toString())) {
					handler.sendVerifyResult(DB_RESULT_EL_NAME, cid_main, cid_packet, (p.getType() == StanzaType.valid),
											 null, p.getStanzaId(), null, false);
					if (p.getType() == StanzaType.valid) {
						authenticatorSelectorManager.authenticateConnection(p.getStanzaId(), cid_conns, cid_packet);

						// As per specification:
						// If the value of the 'type' attribute is "valid", then the connection between the domain pair
						// is considered verified and the Initiating Server can send any outbound stanzas
						// it has queued up for routing to the Receiving Server for the domain pair
						cid_conns.streamNegotiationCompleted(serv);
						serv.streamNegotiationCompleted();
					}
				} else {
					if (log.isLoggable(Level.FINE)) {
						log.log(Level.FINE, "Received verify for {0} but it was not requested!", p.getStanzaFrom());
					}
				}
				if (serv.isHandshakingOnly()) {
					serv.stop();
				}
			}
		}
	}

	/**
	 * Adds domain to list of domains requested for result by service
	 */
	@SuppressWarnings("unchecked")
	private void addToResultRequested(S2SIOService serv, String domain) {
		Set<String> requested = (Set<String>) serv.getSessionData().get(REQUESTED_RESULT_DOMAINS_KEY);

		if (requested == null) {
			Set<String> requested_tmp = new CopyOnWriteArraySet<String>();

			requested = (Set<String>) serv.getSessionData().putIfAbsent(REQUESTED_RESULT_DOMAINS_KEY, requested_tmp);
			if (requested == null) {
				requested = requested_tmp;
			}
		}
		requested.add(domain);
	}

}
