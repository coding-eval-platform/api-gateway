package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import ar.edu.itba.cep.api_gateway.security.bearer.BearerTokenAuthentication;
import ar.edu.itba.cep.api_gateway.security.bearer.TokenEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * An implementation of a {@link TokenEncoder} using the JWT specification.
 */
@Component
public class JwtTokenEncoder implements TokenEncoder {

    @Override
    public Mono<String> encode(final BearerTokenAuthentication bearerTokenAuthentication) {
        // TODO: implement.
        return Mono.empty();
    }
}
