package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.Client;
import com.nimbusds.jose.JWSAlgorithm;

public class DefaultClientJOSEService implements ClientJOSEService{

    @Override
    public JWTVerifier getVerifier(Client client, JWSAlgorithm alg) {
        return null;
    }

    @Override
    public JWTEncrypter getEncrypter(Client client) {
        return null;
    }
}
