package reality.auth;

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import reality.models.PermissionMapping;
import tigase.db.*;
import tigase.xmpp.jid.BareJID;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EpicGamesAuthImpl extends AuthRepositoryImpl {
    private static final Logger log = Logger.getLogger(EpicGamesAuthImpl.class.getName());

    public EpicGamesAuthImpl(UserRepository repo) {
        super(repo);
    }

    private boolean verifyTokenWithPermission(String token, String permission, int action) {
        try {
            // Send HTTP request to get permissions
            HttpResponse<PermissionMapping[]> response = Unirest.get("https://account-public-service-prod.realityfn.org/account/api/oauth/permissions")
                    .header("Authorization", "Bearer " + token)
                    .asObject(PermissionMapping[].class);

            if (response.getStatus() != 200) {
                log.log(Level.WARNING, "HTTP request failed with status: " + response.getStatus() + " - " + response.getStatusText());
                return false;
            }

            // Parse the permissions and return the result
            return Arrays.stream(response.getBody()).anyMatch(x -> {
                // If the requested action is 15 (ALL), short-circuit and return true
                if (x.action == 15) {
                    return true;
                }

                // Opposite for 16 (DENY)
                if ((x.action & 16) != 0) {
                    return false;
                }

                boolean actionMatches = (x.action & action) == action;
                boolean resourceMatches = matchesResourcePattern(x.resource, permission);

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

    @Override
    public void addUser(BareJID user, String password) throws TigaseDBException {
        String domain = user.getDomain();
        String accountId = user.getLocalpart();

        String resource = "xmpp:session:" + domain + ":" + accountId;
        if (verifyTokenWithPermission(password, resource, 1)) {
            super.addUser(user, password);
        }
    }
}
