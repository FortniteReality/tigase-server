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
package tigase.xmpp.impl.push;

import tigase.server.Packet;
import tigase.xml.Element;
import tigase.xmpp.XMPPException;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.jid.BareJID;

public interface PushNotificationsExtension extends PushNotificationsAware {

	boolean shouldSendNotification(Packet packet, BareJID userJid, XMPPResourceConnection session)
			throws XMPPException;
	
	default void prepareNotificationPayload(Element pushServiceSettings, PushNotificationCause cause, Packet packet, long msgCount, Element notification) {
		switch (cause) {
			case ACCOUNT_REMOVED -> {}
			default -> prepareNotificationPayload(pushServiceSettings, packet, msgCount, notification);
		}
	}
	
	default void prepareNotificationPayload(Element pushServiceSettings, Packet packet, long msgCount, Element notification) {}

	default void setPushNotifications(PushNotifications pushNotifications) {}
	
}
