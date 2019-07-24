package ar.edu.itba.cep.api_gateway.security.bearer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.stereotype.Component;

/**
 * An {@link AuthenticationWebFilter} that attempts to authenticate the user performing the request from a bearer token.
 */
@Component
public class BearerTokenAuthenticationWebFilter extends AuthenticationWebFilter {

    /**
     * Constructor.
     *
     * @param bearerTokenAuthenticationManager        The {@link BearerTokenAuthenticationManager} used to authenticate.
     * @param bearerTokenAuthenticationConverter      The {@link BearerTokenAuthenticationConverter}
     *                                                used to get the token from a request.
     * @param bearerTokenAuthenticationFailureHandler The {@link BearerTokenAuthenticationFailureHandler} to be executed
     *                                                if the authentication fails.
     */
    @Autowired
    public BearerTokenAuthenticationWebFilter(
            final BearerTokenAuthenticationManager bearerTokenAuthenticationManager,
            final BearerTokenAuthenticationConverter bearerTokenAuthenticationConverter,
            final BearerTokenAuthenticationFailureHandler bearerTokenAuthenticationFailureHandler) {
        super(bearerTokenAuthenticationManager);
        setServerAuthenticationConverter(bearerTokenAuthenticationConverter);
        setAuthenticationFailureHandler(bearerTokenAuthenticationFailureHandler);
    }
}
