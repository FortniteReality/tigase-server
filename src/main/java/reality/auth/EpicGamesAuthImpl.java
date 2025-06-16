package reality.auth;

import org.osgi.service.device.Match;
import reality.models.PermissionMapping;
import tigase.auth.XmppSaslException;
import tigase.db.*;
import tigase.util.Algorithms;
import tigase.util.Base64;
import tigase.xmpp.jid.BareJID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.security.auth.callback.*;
import javax.security.sasl.*;
import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EpicGamesAuthImpl
        implements AuthRepository {

    protected static final Logger log = Logger.getLogger("reality.auth.EpicGamesAuthImpl");
    protected static final String PASSWORD_KEY = "password";
    private static final String[] non_sasl_mechs = {"password", "digest"};
    private static final String[] sasl_mechs = {"PLAIN", "DIGEST-MD5", "CRAM-MD5"};

    // ~--- fields ---------------------------------------------------------------
    private UserRepository repo = null;

    /**
     * Creates a new <code>AuthRepositoryImpl</code> instance.
     */
    public EpicGamesAuthImpl(UserRepository repo) {
        this.repo = repo;
    }

    public EpicGamesAuthImpl() {
        this.repo = null;
    }

    private boolean verifyTokenWithPermission(String token, String permission, int action) {
        try {
            // Create HttpClient
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Create HttpRequest to permissions endpoint with method and token
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://account-public-service-prod.realityfn.org/account/api/oauth/permissions"))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            // Send request and get the response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.log(Level.WARNING, "HTTP request failed with status: " + response.statusCode() + " - " + response.body());
                return false;
            }

            log.log(Level.FINEST, "Got response body {0}", response.body());

            // Parse JSON response to Permission array
            PermissionMapping[] permissions = parsePermissionsFromJson(response.body());

            log.log(Level.FINEST, "Response has {0} permissions", permissions.length);

            // Parse the permissions and return the result
            return Arrays.stream(permissions).anyMatch(x -> {
                log.log(Level.FINEST, "Token {0} has resource {1} with action {2}", new Object[] {token, x.resource, x.action});

                boolean actionMatches = (x.action & action) == action;
                boolean resourceMatches = matchesResourcePattern(x.resource, permission);

                if (resourceMatches) {
                    // If the requested action is 15 (ALL), short-circuit and return true
                    if (x.action == 15) {
                        return true;
                    }

                    // Opposite for 16 (DENY)
                    if ((x.action & 16) != 0) {
                        return false;
                    }
                }

                return resourceMatches && actionMatches;
            });
        }
        catch (Exception e) {
            log.log(Level.WARNING, "Error when trying to retrieve token permissions.\n" + e.getMessage());
            return false;
        }
    }

    private boolean matchesResourcePattern(String permissionResource, String requestedResource) {
        // This part is optional, but saves some cpu cycles so might as well include it
        if (permissionResource.equals(requestedResource)) {
            return true;
        }

        String regexPattern = permissionResource.replace("*", ".*");
        regexPattern = "^" + regexPattern + "$";

        try {
            return requestedResource.matches(regexPattern);
        }
        catch (Exception e) {
            return false; // Should never happen
        }
    }

    private PermissionMapping[] parsePermissionsFromJson(String jsonString) {
        List<PermissionMapping> permissions = new ArrayList<>();

        // Remove the outer brackets and whitespace
        jsonString = jsonString.trim();
        if (jsonString.startsWith("[")) {
            jsonString = jsonString.substring(1);
        }
        if (jsonString.endsWith("]")) {
            jsonString = jsonString.substring(0, jsonString.length() - 1);
        }

        // Split by objects (looking for },{ pattern)
        String[] objects = jsonString.split("\\},\\s*\\{");

        for (String obj : objects) {
            // Clean up the object string
            obj = obj.trim();
            if (!obj.startsWith("{")) {
                obj = "{" + obj;
            }
            if (!obj.endsWith("}")) {
                obj = obj + "}";
            }

            // Extract the permissions manually
            PermissionMapping mapping = new PermissionMapping();

            // Extract the action - we are looking for "action":number
            String actionPattern = "\"action\"\\s*:\\s*(\\d+)";
            Pattern pattern = Pattern.compile(actionPattern);
            Matcher matcher = pattern.matcher(obj);
            if (matcher.find()) {
                mapping.action = Integer.parseInt(matcher.group(1));
            }

            // Extract resource (looking for "resource":"value")
            String resourcePattern = "\"resource\"\\s*:\\s*\"([^\"]+)\"";
            pattern = java.util.regex.Pattern.compile(resourcePattern);
            matcher = pattern.matcher(obj);
            if (matcher.find()) {
                mapping.resource = matcher.group(1);
            }

            permissions.add(mapping);
        }

        return permissions.toArray(new PermissionMapping[0]);
    }

    @Override
    public void loggedIn(BareJID jid) throws TigaseDBException {

    }

    @Override
    public void addUser(BareJID user, final String password) throws UserExistsException, TigaseDBException {
        // Unneeded
    }

    @Override
    public boolean isMechanismSupported(String domain, String mechanism) {
        if ("PLAIN".equals(mechanism)) {
            return true;
        }

        return true;
    }

    @Override
    public String getResourceUri() {
        return "epic-games://token-auth";
    }

    @Override
    public long getActiveUsersCountIn(Duration duration) {
        return -1;
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
    @Deprecated
    public void initRepository(final String string, Map<String, String> params) throws DBInitException {
    }

    @Override
    public void logout(BareJID user) {
    }

    @Override
    public boolean otherAuth(final Map<String, Object> props)
            throws UserNotFoundException, TigaseDBException, AuthorizationException {
        if (log.isLoggable(Level.FINEST)) {
            log.log(Level.FINEST, "otherAuth: {0}", props);
        }

        String proto = (String) props.get(PROTOCOL_KEY);

        // TODO: this equals should be most likely replaced with == here.
        // The property value is always set using the constant....
        if (proto.equals(PROTOCOL_VAL_SASL)) {
            log.log(Level.WARNING, "WE ARE SO FUCKED THIS IS USING SASL!!");
            return saslAuth(props);
        }    // end of if (proto.equals(PROTOCOL_VAL_SASL))
        if (proto.equals(PROTOCOL_VAL_NONSASL)) {
            String password = (String) props.get(PASSWORD_KEY);
            BareJID user_id = (BareJID) props.get(USER_ID_KEY);

            if (password != null) {
                return plainAuth(user_id, password);
            }

            String digest = (String) props.get(DIGEST_KEY);

            if (digest != null) {
                String digest_id = (String) props.get(DIGEST_ID_KEY);

                return digestAuth(user_id, digest, digest_id, "SHA");
            }
        }    // end of if (proto.equals(PROTOCOL_VAL_SASL))

        throw new AuthorizationException("Protocol is not supported.");
    }

    @Override
    public void queryAuth(final Map<String, Object> authProps) {
        String protocol = (String) authProps.get(PROTOCOL_KEY);

        if (protocol.equals(PROTOCOL_VAL_NONSASL)) {
            authProps.put(RESULT_KEY, non_sasl_mechs);
        }    // end of if (protocol.equals(PROTOCOL_VAL_NONSASL))
        if (protocol.equals(PROTOCOL_VAL_SASL)) {
            authProps.put(RESULT_KEY, sasl_mechs);
        }    // end of if (protocol.equals(PROTOCOL_VAL_NONSASL))
    }

    @Override
    public void removeUser(BareJID user) throws UserNotFoundException, TigaseDBException {
        // Not needed
    }

    // Implementation of tigase.db.AuthRepository

    @Override
    public void updatePassword(BareJID user, final String password) throws TigaseDBException {
        // Passwords are handled by access tokens which shouldn't be updated
    }

    public String getPassword(BareJID user) throws UserNotFoundException, TigaseDBException {
        return ""; // This shouldn't be needed if we're not doing digest auth
    }

    @Override
    public AccountStatus getAccountStatus(BareJID user) throws TigaseDBException {
        return AccountStatus.active;
    }

    @Override
    public boolean isUserDisabled(BareJID user) throws UserNotFoundException, TigaseDBException {
        return false;
    }

    @Override
    public void setAccountStatus(BareJID user, AccountStatus value) throws TigaseDBException {
        // Unneeded rn
    }

    @Override
    public void setUserDisabled(BareJID user, Boolean value) throws UserNotFoundException, TigaseDBException {
        // Unneeded rn
    }

    private boolean digestAuth(BareJID user, final String digest, final String id, final String alg)
            throws UserNotFoundException, TigaseDBException, AuthorizationException {
        final String db_password = getPassword(user);

        try {
            final String digest_db_pass = Algorithms.hexDigest(id, db_password, alg);

            if (log.isLoggable(Level.FINEST)) {
                log.finest("Comparing passwords, given: " + digest + ", db: " + digest_db_pass);
            }

            return digest.equals(digest_db_pass);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthorizationException("No such algorithm.", e);
        }    // end of try-catch
    }

    private boolean plainAuth(BareJID user, final String password) throws TigaseDBException {
        if (log.isLoggable(Level.FINEST)) {
            log.log(Level.FINEST, "plainAuth: {0}:{1}", new Object[]{user, password});
        }

        String resource = "xmpp:session:" + user.getDomain() + ":" + user.getLocalpart();
        return verifyTokenWithPermission(password, resource, 1);
    }

    // ~--- methods --------------------------------------------------------------
    private boolean saslAuth(final Map<String, Object> props) throws AuthorizationException {
        try {
            SaslServer ss = (SaslServer) props.get("SaslServer");

            if (ss == null) {
                Map<String, String> sasl_props = new TreeMap<String, String>();

                sasl_props.put(Sasl.QOP, "auth");
                ss = Sasl.createSaslServer((String) props.get(MACHANISM_KEY), "xmpp",
                        (String) props.get(SERVER_NAME_KEY), sasl_props,
                        new reality.auth.EpicGamesAuthImpl.SaslCallbackHandler(props));
                props.put("SaslServer", ss);
            }    // end of if (ss == null)

            String data_str = (String) props.get(DATA_KEY);
            byte[] in_data = ((data_str != null) ? Base64.decode(data_str) : new byte[0]);

            if (log.isLoggable(Level.FINEST)) {
                log.finest("response: " + new String(in_data));
            }

            byte[] challenge = ss.evaluateResponse(in_data);

            if (log.isLoggable(Level.FINEST)) {
                log.finest("challenge: " + ((challenge != null) ? new String(challenge) : "null"));
            }

            String challenge_str = (((challenge != null) && (challenge.length > 0)) ? Base64.encode(challenge) : null);

            props.put(RESULT_KEY, challenge_str);
            if (ss.isComplete()) {
                return true;
            } else {
                return false;
            }    // end of if (ss.isComplete()) else
        } catch (SaslException e) {
            throw new AuthorizationException("Sasl exception.", e);
        }      // end of try-catch
    }

    private class SaslCallbackHandler
            implements CallbackHandler {

        private Map<String, Object> options = null;

        private SaslCallbackHandler(final Map<String, Object> options) {
            this.options = options;
        }

        @Override
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            BareJID jid = null;

            for (int i = 0; i < callbacks.length; i++) {
                if (log.isLoggable(Level.FINEST)) {
                    log.finest("Callback: " + callbacks[i].getClass().getSimpleName());
                }
                if (callbacks[i] instanceof RealmCallback) {
                    RealmCallback rc = (RealmCallback) callbacks[i];
                    String realm = (String) options.get(REALM_KEY);

                    if (realm != null) {
                        rc.setText(realm);
                    }        // end of if (realm == null)
                    if (log.isLoggable(Level.FINEST)) {
                        log.finest("RealmCallback: " + realm);
                    }
                } else {
                    if (callbacks[i] instanceof NameCallback) {
                        NameCallback nc = (NameCallback) callbacks[i];
                        String user_name = nc.getName();

                        if (user_name == null) {
                            user_name = nc.getDefaultName();
                        }      // end of if (name == null)
                        jid = BareJID.bareJIDInstanceNS(user_name, (String) options.get(REALM_KEY));

                        try {
                            final AccountStatus accountStatus = getAccountStatus(jid);
                            if (accountStatus.isInactive()) {
                                throw XmppSaslException.getExceptionFor(accountStatus);
                            }
                        } catch (TigaseDBException e) {
                            throw new IOException("Account Status retrieving problem.", e);
                        }

                        options.put(USER_ID_KEY, jid);
                        if (log.isLoggable(Level.FINEST)) {
                            log.finest("NameCallback: " + user_name);
                        }
                    } else {
                        if (callbacks[i] instanceof PasswordCallback) {
                            PasswordCallback pc = (PasswordCallback) callbacks[i];

                            try {
                                String passwd = getPassword(jid);

                                pc.setPassword(passwd.toCharArray());
                                if (log.isLoggable(Level.FINEST)) {
                                    log.finest("PasswordCallback: " + passwd);
                                }
                            } catch (Exception e) {
                                throw new IOException("Password retrieving problem.", e);
                            }    // end of try-catch
                        } else {
                            if (callbacks[i] instanceof AuthorizeCallback) {
                                AuthorizeCallback authCallback = ((AuthorizeCallback) callbacks[i]);
                                String authenId = authCallback.getAuthenticationID();
                                String authorId = authCallback.getAuthorizationID();

                                if (log.isLoggable(Level.FINEST)) {
                                    log.finest("AuthorizeCallback: authenId: " + authenId);
                                    log.finest("AuthorizeCallback: authorId: " + authorId);
                                }

                                // if (authenId.equals(authorId)) {
                                authCallback.setAuthorized(true);

                                // } // end of if (authenId.equals(authorId))
                            } else {
                                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
                            }
                        }
                    }
                }
            }
        }
    }
}    // EpicGamesAuthImpl