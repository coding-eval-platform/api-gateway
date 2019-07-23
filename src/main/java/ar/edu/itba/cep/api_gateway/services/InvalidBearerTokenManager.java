package ar.edu.itba.cep.api_gateway.services;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * A manager in charge of keeping record of invalidated bearer tokens.
 */
@Component
public class InvalidBearerTokenManager implements InvalidatedBearerTokenChecker {

    @Override
    public Mono<Boolean> isInvalid(final UUID tokenId) {
        // TODO: implement
        return Mono.just(false);
    }
}
