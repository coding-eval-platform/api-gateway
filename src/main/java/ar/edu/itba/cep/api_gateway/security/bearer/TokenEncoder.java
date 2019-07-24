package ar.edu.itba.cep.api_gateway.security.bearer;

import reactor.core.publisher.Mono;

/**
 * Defines behaviour for an object that can encode a {@link BearerTokenAuthentication} into a {@link String}.
 */
public interface TokenEncoder {

    /**
     * Encodes the given {@code bearerTokenAuthentication}.
     *
     * @param bearerTokenAuthentication The {@link BearerTokenAuthentication} to be encoded.
     * @return A {@link Mono} of {@link String} representing encoded token.
     */
    Mono<String> encode(final BearerTokenAuthentication bearerTokenAuthentication);
}
