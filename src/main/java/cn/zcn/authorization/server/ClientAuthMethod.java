package cn.zcn.authorization.server;

import java.util.HashMap;
import java.util.Map;

public enum ClientAuthMethod {
    SECRET_POST("client_secret_post"),
    SECRET_BASIC("client_secret_basic"),
    SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY("private_key_jwt"),
    NONE("none");

    private final String value;

    private static final Map<String, ClientAuthMethod> lookup = new HashMap<>();

    static {
        for (ClientAuthMethod a : ClientAuthMethod.values()) {
            lookup.put(a.getValue(), a);
        }
    }

    ClientAuthMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static ClientAuthMethod getByValue(String value) {
        return lookup.get(value);
    }
}
