package ar.edu.itba.cep.api_gateway.security.bearer;

import reactor.core.publisher.Mono;

/**
 * Defines behaviour for an object that can decode a {@link BearerTokenAuthentication} from a {@link String}.
 */
public interface TokenDecoder {

    /**
     * decodes the given {@code rawToken}.
     *
     * @param rawToken The raw token to be decoded.
     * @return A {@link Mono} of {@link BearerTokenAuthentication} if the token can be decoded, or empty otherwise.
     */
    Mono<BearerTokenAuthentication> decode(final String rawToken);
}
