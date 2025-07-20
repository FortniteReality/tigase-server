package reality.auth;

import reality.models.PermissionMapping;
import tigase.auth.XmppSaslException;
import tigase.db.*;
import tigase.server.Iq;
import tigase.server.Packet;
import tigase.util.Algorithms;
import tigase.util.Base64;
import tigase.util.stringprep.TigaseStringprepException;
import tigase.xml.Element;
import tigase.xmpp.StanzaType;
import tigase.xmpp.XMPPException;
import tigase.xmpp.XMPPResourceConnection;
import tigase.xmpp.impl.BindResource;
import tigase.xmpp.jid.BareJID;
import tigase.xmpp.jid.JID;

import javax.security.auth.callback.*;
import javax.security.sasl.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EpicGamesAuthImpl implements AuthRepository {

    protected static final Logger log = Logger.getLogger("reality.auth.EpicGamesAuthImpl");

    private static final String[] sasl_mechs = {"PLAIN"};

    private final UserRepository repo;

    public EpicGamesAuthImpl() {
        repo = new EpicUserRepositoryImpl();
    }

    /**
     * Creates a new EpicGamesAuthImpl instance.
     * @param repo The user repository to use for storing user data. This is injected
     *             from the server configuration (config.tdsl).
     */
    public EpicGamesAuthImpl(UserRepository repo) {
        if (repo == null) {
            throw new IllegalArgumentException("UserRepository cannot be null.");
        }
        this.repo = repo;
    }

    @Override
    public boolean otherAuth(final Map<String, Object> props)
            throws UserNotFoundException, TigaseDBException, AuthorizationException {
        String proto = (String) props.get(PROTOCOL_KEY);

        if (PROTOCOL_VAL_SASL.equals(proto)) {
            return saslAuth(props);
        }
        if (PROTOCOL_VAL_NONSASL.equals(proto)) {
            String password = (String) props.get(PASSWORD_KEY);
            BareJID user_id = (BareJID) props.get(USER_ID_KEY);
            if (password != null) {
                return plainAuth(user_id, password);
            }
        }
        throw new AuthorizationException("Unsupported authentication protocol.");
    }

    private boolean plainAuth(BareJID user, final String password) throws TigaseDBException {
        if (user == null || password == null || password.isEmpty()) {
            return false;
        }

        String resource = "xmpp:session:" + user.getDomain() + ":" + user.getLocalpart();
        boolean tokenVerified = verifyTokenWithPermission(password, resource, 1);
        if (tokenVerified) {
            try {
                if (!repo.userExists(user)) {
                    repo.addUser(user);
                    repo.setData(user, "password", password);
                } else {
                    repo.setData(user, "password", password);
                }
            } catch (UserExistsException | UserNotFoundException e) {
                log.log(Level.SEVERE, "Repository error during plain auth for " + user, e);
            }
        }
        return tokenVerified;
    }

    private boolean saslAuth(final Map<String, Object> props) throws AuthorizationException {
        try {
            SaslServer ss = (SaslServer) props.get("SaslServer");
            if (ss == null) {
                Map<String, String> sasl_props = new TreeMap<>();
                sasl_props.put(Sasl.QOP, "auth");
                ss = Sasl.createSaslServer((String) props.get(MACHANISM_KEY), "xmpp",
                        (String) props.get(SERVER_NAME_KEY), sasl_props,
                        new SaslCallbackHandler(props));
                props.put("SaslServer", ss);
            }

            String data_str = (String) props.get(DATA_KEY);
            byte[] in_data = (data_str != null) ? Base64.decode(data_str) : new byte[0];
            byte[] challenge = ss.evaluateResponse(in_data);
            String challenge_str = ((challenge != null) && (challenge.length > 0)) ? Base64.encode(challenge) : null;
            props.put(RESULT_KEY, challenge_str);

            return ss.isComplete();
        } catch (SaslException e) {
            throw new AuthorizationException("Sasl exception.", e);
        }
    }

    @Override
    public String getPassword(BareJID user) throws UserNotFoundException, TigaseDBException {
        String password = repo.getData(user, "password");
        if (password == null) {
            throw new UserNotFoundException("Password not found for user " + user);
        }
        return password;
    }

    @Override
    public void addUser(BareJID user, final String password) throws UserExistsException, TigaseDBException {
        repo.addUser(user);
        try {
            repo.setData(user, "password", password);
        } catch (UserNotFoundException e) {
            throw new TigaseDBException("Failed to set password for newly created user.", e);
        }
    }

    @Override
    public void removeUser(BareJID user) throws UserNotFoundException, TigaseDBException {
        repo.removeUser(user);
    }

    @Override
    public long getUsersCount() {
        return repo.getUsersCount();
    }

    @Override
    public long getUsersCount(String domain) {
        return repo.getUsersCount(domain);
    }

    @Override
    public AccountStatus getAccountStatus(BareJID user) throws TigaseDBException {
        // we assume all accounts are always active.
        return AccountStatus.active;
    }

    // --- Unneeded Methods ---

    @Override
    public void updatePassword(BareJID user, final String password) throws TigaseDBException {
        // Not needed. The token is updated during plainAuth, and thus should not be changed.
    }
    @Override
    public void setAccountStatus(BareJID user, AccountStatus value) throws TigaseDBException {
        // Not needed.
    }
    @Override
    public void loggedIn(BareJID jid) throws TigaseDBException { }
    @Override
    public void logout(BareJID user) { }
    @Override
    public boolean isMechanismSupported(String domain, String mechanism) { return true; }
    @Override
    public String getResourceUri() { return "epic-games://token-auth"; }
    @Override
    public long getActiveUsersCountIn(Duration duration) { return -1; }
    @Override
    public void initRepository(final String string, Map<String, String> params) throws DBInitException { }
    @Override
    public void queryAuth(final Map<String, Object> authProps) {
        authProps.put(RESULT_KEY, sasl_mechs);
    }
    @Override
    public boolean isUserDisabled(BareJID user) throws UserNotFoundException, TigaseDBException { return false; }
    @Override
    public void setUserDisabled(BareJID user, Boolean value) throws UserNotFoundException, TigaseDBException {}


    private boolean verifyTokenWithPermission(String token, String permission, int action) {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://account-public-service-prod.realityfn.org/account/api/oauth/permissions"))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.log(Level.WARNING, "HTTP request failed with status: {0} - {1}", new Object[]{response.statusCode(), response.body()});
                return false;
            }
            PermissionMapping[] permissions = parsePermissionsFromJson(response.body());
            return Arrays.stream(permissions).anyMatch(x -> {
                boolean actionMatches = (x.action & action) == action;
                boolean resourceMatches = matchesResourcePattern(x.resource, permission);
                if (resourceMatches) {
                    if (x.action == 15) return true;
                    if ((x.action & 16) != 0) return false;
                }
                return resourceMatches && actionMatches;
            });
        } catch (Exception e) {
            log.log(Level.WARNING, "Error when trying to retrieve token permissions.", e);
            return false;
        }
    }

    private boolean matchesResourcePattern(String permissionResource, String requestedResource) {
        if (permissionResource.equals(requestedResource)) return true;
        String regexPattern = "^" + permissionResource.replace("*", ".*") + "$";
        try {
            return requestedResource.matches(regexPattern);
        } catch (Exception e) {
            return false;
        }
    }

    private PermissionMapping[] parsePermissionsFromJson(String jsonString) {
        List<PermissionMapping> permissions = new ArrayList<>();
        jsonString = jsonString.trim();
        if (jsonString.startsWith("[")) jsonString = jsonString.substring(1);
        if (jsonString.endsWith("]")) jsonString = jsonString.substring(0, jsonString.length() - 1);
        String[] objects = jsonString.split("\\},\\s*\\{");
        for (String objStr : objects) {
            String obj = objStr.trim();
            if (!obj.startsWith("{")) obj = "{" + obj;
            if (!obj.endsWith("}")) obj = obj + "}";
            PermissionMapping mapping = new PermissionMapping();
            Matcher actionMatcher = Pattern.compile("\"action\"\\s*:\\s*(\\d+)").matcher(obj);
            if (actionMatcher.find()) mapping.action = Integer.parseInt(actionMatcher.group(1));
            Matcher resourceMatcher = Pattern.compile("\"resource\"\\s*:\\s*\"([^\"]+)\"").matcher(obj);
            if (resourceMatcher.find()) mapping.resource = resourceMatcher.group(1);
            if (mapping.resource != null) permissions.add(mapping);
        }
        return permissions.toArray(new PermissionMapping[0]);
    }

    private class SaslCallbackHandler implements CallbackHandler {
        private final Map<String, Object> options;
        private SaslCallbackHandler(final Map<String, Object> options) { this.options = options; }
        @Override
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            BareJID jid = null;
            for (Callback callback : callbacks) {
                if (callback instanceof RealmCallback) {
                    ((RealmCallback) callback).setText((String) options.get(REALM_KEY));
                } else if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    String userName = nc.getDefaultName();
                    if (userName == null) userName = nc.getName();
                    jid = BareJID.bareJIDInstanceNS(userName, (String) options.get(REALM_KEY));
                    options.put(USER_ID_KEY, jid);
                    try {
                        if (getAccountStatus(jid).isInactive()) {
                            throw XmppSaslException.getExceptionFor(getAccountStatus(jid));
                        }
                    } catch (TigaseDBException e) {
                        throw new IOException("Account status retrieving problem.", e);
                    }
                } else if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    jid = (BareJID) options.get(USER_ID_KEY);
                    try {
                        pc.setPassword(getPassword(jid).toCharArray());
                    } catch (UserNotFoundException e) {
                    } catch (TigaseDBException e) {
                        throw new IOException("Password retrieving problem.", e);
                    }
                } else if (callback instanceof AuthorizeCallback) {
                    ((AuthorizeCallback) callback).setAuthorized(true);
                } else {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                }
            }
        }
    }
}