package cn.zcn.authorization.server.authentication.provider;

import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.ClientService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Collections;

public class ClientSecretAuthenticationProvider implements AuthenticationProvider {

    private ClientService clientService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String clientId = authentication.getPrincipal().toString();
        String clientSecret = authentication.getCredentials().toString();

        try {
            Client client = clientService.loadClientByClientId(clientId);

            String storedClientSecret = client.getClientSecret();

            if (storedClientSecret.equals(clientSecret)) {
                return new UsernamePasswordAuthenticationToken(clientId, storedClientSecret, Collections.emptyList());
            }

            throw new AuthenticationServiceException("Client secret mismatch.");
        } catch (Exception e) {
            throw new AuthenticationServiceException("Client secret mismatch.", e);
        }
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }

    public void setClientService(ClientService clientService) {
        this.clientService = clientService;
    }
}
