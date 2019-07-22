package ar.edu.itba.cep.api_gateway.security.bearer;

import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.stereotype.Component;

/**
 * A {@link org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler}
 * that uses a {@link BearerTokenAuthenticationEntryPoint} to handle the authentication failure.
 */
@Component
public class BearerTokenAuthenticationFailureHandler extends ServerAuthenticationEntryPointFailureHandler {

    /**
     * Constructor.
     *
     * @param bearerTokenAuthenticationEntryPoint A {@link BearerTokenAuthenticationEntryPoint}
     *                                            used to handle the authentication failure.
     */
    public BearerTokenAuthenticationFailureHandler(
            final BearerTokenAuthenticationEntryPoint bearerTokenAuthenticationEntryPoint) {
        super(bearerTokenAuthenticationEntryPoint);
    }
}
