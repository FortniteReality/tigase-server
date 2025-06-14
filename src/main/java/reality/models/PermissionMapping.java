package reality.models;

public class PermissionMapping {
    public String resource;
    public int action;

    public PermissionMapping() {
        this.resource = "";
        this.action = 0;
    }

    public PermissionMapping(String resource, int action) {
        this.resource = resource;
        this.action = action;
    }
}
