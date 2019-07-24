package ar.edu.itba.cep.api_gateway.services;

import java.util.UUID;

/**
 * Defines behaviour for an object that can invalidate bearer tokens.
 */
public interface BearerTokenInvalidator {

    /**
     * Blacklists the token with the given {@code tokenId}.
     *
     * @param tokenId The token's id.
     */
    void invalidateToken(final UUID tokenId);
}
