package cn.zcn.authorization.server.authentication.provider;

import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.ClientService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ClientSecretAuthenticationProvider implements AuthenticationProvider {

    private final ClientService clientService;

    public ClientSecretAuthenticationProvider(ClientService clientService) {
        this.clientService = clientService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String clientId = authentication.getPrincipal().toString();
        String clientSecret = authentication.getCredentials().toString();

        try {
            Client client = clientService.loadClientByClientId(clientId);

            String storedClientSecret = client.getClientSecret();

            if (storedClientSecret.equals(clientSecret)) {
                return new UsernamePasswordAuthenticationToken(clientId, storedClientSecret, client.getAuthorities());
            }

            throw new BadCredentialsException("Mismatch client secret.");
        } catch (Exception e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
