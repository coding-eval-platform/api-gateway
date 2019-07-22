package ar.edu.itba.cep.api_gateway.security.bearer;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * A {@link ServerAuthenticationEntryPoint} that handles authentication requests
 * requiring the user to send a Bearer Token (a 401 Unauthorized request is returned in the response).
 */
@Component
public class BearerTokenAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(
            final ServerWebExchange exchange,
            final AuthenticationException authenticationException) {

        return Mono.defer(
                () -> {
                    final var response = exchange.getResponse();

                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    response.getHeaders().set(
                            HttpHeaders.WWW_AUTHENTICATE,
                            Constants.BEARER_SCHEME + " error=\"invalid_token\""
                    );
                    // TODO: Improve the WWW-Authenticate header.
                    //  Check RFC2617 and RFC6750 (even though we don't really use Oauth2).

                    return response.setComplete();
                }
        );
    }
}
