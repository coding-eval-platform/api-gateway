package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import ar.edu.itba.cep.api_gateway.security.bearer.BearerTokenAuthentication;
import ar.edu.itba.cep.api_gateway.security.bearer.TokenDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * An implementation of a {@link TokenDecoder} using the JWT specification.
 */
@Component
public class JwtTokenDecoder implements TokenDecoder {

    @Override
    public Mono<BearerTokenAuthentication> decode(String rawToken) {
        // TODO: implement.
        return Mono.empty();
    }
}
