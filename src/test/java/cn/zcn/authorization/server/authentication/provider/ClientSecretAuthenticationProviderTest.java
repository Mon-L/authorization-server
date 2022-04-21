package cn.zcn.authorization.server.authentication.provider;

import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.ClientService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ClientSecretAuthenticationProviderTest {

    private Client client;
    private ClientService clientService;
    private AuthenticationProvider authenticationProvider;

    @BeforeEach
    public void beforeEach() {
        client = Mockito.mock(Client.class);
        Mockito.when(client.getClientId()).thenReturn("client");
        Mockito.when(client.getClientSecret()).thenReturn("secret");

        clientService = Mockito.mock(ClientService.class);
        Mockito.when(clientService.loadClientByClientId(client.getClientId())).thenReturn(client);

        authenticationProvider = Mockito.spy(new ClientSecretAuthenticationProvider(clientService));
    }

    @Test
    public void testSupports() {
        Assertions.assertThat(authenticationProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
        Assertions.assertThat(authenticationProvider.supports(IllegalArgumentException.class)).isFalse();
    }

    @Test
    public void testAuthenticateWithInvalidClientId() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("foo", "bar");
        Assertions.assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(() -> authenticationProvider.authenticate(authenticationToken));
    }

    @Test
    public void testAuthenticateWithInvalidClientSecret() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(client.getClientId(), "bar");
        Assertions.assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(() -> authenticationProvider.authenticate(authenticationToken))
                .withMessage("Mismatch client secret.");
    }

    @Test
    public void testAuthenticationThenSuccess() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret());
        Authentication authentication = authenticationProvider.authenticate(authenticationToken);

        Assertions.assertThat(authentication).isNotNull();
        Assertions.assertThat(authentication.getPrincipal()).isEqualTo(client.getClientId());
        Assertions.assertThat(authentication.getCredentials()).isEqualTo(client.getClientSecret());
    }
}
