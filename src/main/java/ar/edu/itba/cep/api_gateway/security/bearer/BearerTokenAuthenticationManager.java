package ar.edu.itba.cep.api_gateway.security.bearer;

import ar.edu.itba.cep.api_gateway.security.AnonymousAccess;
import ar.edu.itba.cep.api_gateway.services.InvalidatedBearerTokenChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import reactor.core.publisher.Mono;


/**
 * A {@link ReactiveAuthenticationManager} that tries to authenticate a {@link PreAuthenticatedBearerToken} using
 * a {@link TokenDecoder}, which is called with the {@link PreAuthenticatedBearerToken#getRawToken()} value.
 */
@Component
public class BearerTokenAuthenticationManager implements ReactiveAuthenticationManager {

    /**
     * The {@link TokenDecoder} used to create a {@link BearerTokenAuthentication} from a raw token.
     */
    private final TokenDecoder tokenDecoder;
    /**
     * The {@link InvalidatedBearerTokenChecker} used to check whether a token is invalid
     * or it can be used to authenticate a request.
     */
    private final InvalidatedBearerTokenChecker invalidTokenChecker;


    /**
     * Constructor.
     *
     * @param tokenDecoder        The {@link TokenDecoder} used to create a {@link BearerTokenAuthentication}
     *                            from a raw token.
     * @param invalidTokenChecker The {@link InvalidatedBearerTokenChecker} used to check whether a token is invalid
     *                            or it can be used to authenticate a request.
     */
    @Autowired
    public BearerTokenAuthenticationManager(
            final TokenDecoder tokenDecoder,
            final InvalidatedBearerTokenChecker invalidTokenChecker) {
        this.tokenDecoder = tokenDecoder;
        this.invalidTokenChecker = invalidTokenChecker;
    }


    @Override
    public Mono<Authentication> authenticate(final Authentication authentication) {

        if (ClassUtils.isAssignable(PreAuthenticatedBearerToken.class, authentication.getClass())) {
            final var preAuthenticatedAuthenticationToken = (PreAuthenticatedBearerToken) authentication;
            final var rawToken = preAuthenticatedAuthenticationToken.getRawToken();
            return tokenDecoder.decode(rawToken)
                    .switchIfEmpty(DECODING_ERROR)
                    .filterWhen(token -> invalidTokenChecker.isInvalid(token.getTokenId()).map(flag -> !flag))
                    .switchIfEmpty(BLACKLISTED_ERROR)
                    .doOnNext(BearerTokenAuthentication::authenticate)
                    .cast(Authentication.class)
                    ;
        }
        return Mono.justOrEmpty(authentication).defaultIfEmpty(AnonymousAccess.getInstance());
    }


    /**
     * A {@link Mono} of {@link BearerTokenAuthentication}
     * with an error to indicate that a raw token could not be decoded into a {@link BearerTokenAuthentication}.
     */
    private static Mono<? extends BearerTokenAuthentication> DECODING_ERROR =
            Mono.defer(() -> Mono.error(new BearerTokenAuthenticationException("Token could not be decoded")));

    /**
     * A {@link Mono} of {@link BearerTokenAuthentication}
     * with an error to indicate that a {@link BearerTokenAuthentication} was invalidated.
     */
    private static Mono<? extends BearerTokenAuthentication> BLACKLISTED_ERROR =
            Mono.defer(() -> Mono.error(new BearerTokenAuthenticationException("Blacklisted token")));

}
