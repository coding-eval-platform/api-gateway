package ar.edu.itba.cep.api_gateway.services;

import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Defines behaviour for an object that can verify if a bearer token is invalid.
 */
public interface InvalidatedBearerTokenChecker {

    /**
     * Indicates whether the token with the given {@code tokenId} is invalid.
     *
     * @param tokenId The token's id.
     * @return {@code true} if the token is invalid, or {@code false} otherwise.
     */
    Mono<Boolean> isInvalid(final UUID tokenId);
}
