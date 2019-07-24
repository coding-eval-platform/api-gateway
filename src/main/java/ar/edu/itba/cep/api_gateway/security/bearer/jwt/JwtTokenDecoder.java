package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import ar.edu.itba.cep.api_gateway.security.bearer.BearerTokenAuthentication;
import ar.edu.itba.cep.api_gateway.security.bearer.TokenDecoder;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static ar.edu.itba.cep.api_gateway.security.bearer.jwt.Constants.ROLES_CLAIM;

/**
 * An implementation of a {@link TokenDecoder} using the JWT specification.
 */
@Component
public class JwtTokenDecoder implements TokenDecoder {

    /**
     * The {@link PublicKey} used to verify external tokens.
     */
    private final PublicKey publicKey;
    /**
     * A {@link JwtHandlerAdapter} used to handle the decoding process.
     */
    private final JwtHandlerAdapter<Jws<Claims>> jwtHandlerAdapter;


    /**
     * Constructor.
     *
     * @param publicKey The {@link PublicKey} used to verify external tokens.
     */
    @Autowired
    public JwtTokenDecoder(final PublicKey publicKey) {
        this.publicKey = publicKey;
        this.jwtHandlerAdapter = new CustomJwtHandlerAdapter();
    }


    @Override
    public Mono<BearerTokenAuthentication> decode(final String rawToken) {
        Assert.hasText(rawToken, "The token must not be null or empty");
        return Mono.just(rawToken)
                .map(token -> Jwts.parser().setSigningKey(publicKey).parse(token, jwtHandlerAdapter))
                .map(Jws::getBody)
                .map(claims -> {
                    // Previous step validated the following values
                    final var tokenId = UUID.fromString(claims.getId());
                    final var username = claims.getSubject();
                    @SuppressWarnings("unchecked") final var roles = (Set<String>) claims.get(ROLES_CLAIM, Set.class);

                    return new BearerTokenAuthentication(tokenId, username, roles);
                })
                .onErrorResume(JwtException.class, ignored -> Mono.defer(Mono::empty))
                ;
    }

    /**
     * Custom implementation of {@link JwtHandlerAdapter} that will validate the token.
     */
    private static class CustomJwtHandlerAdapter extends JwtHandlerAdapter<Jws<Claims>> {

        @Override
        public Jws<Claims> onClaimsJws(final Jws<Claims> jws) {
            final var header = jws.getHeader();
            final var claims = jws.getBody();

            // Check jti is not missing
            final var jtiString = claims.getId();
            if (!StringUtils.hasText(jtiString)) {
                throw new MissingClaimException(header, claims, "Missing \"jwt id\" claim");
            }
            try {
                UUID.fromString(jtiString); // Throws an IllegalArgumentException if the String is not a valid UUID
            } catch (final IllegalArgumentException e) {
                throw new MalformedJwtException("The \"jwt id\" claim must be a valid UUID", e);
            }

            // Check roles is not missing
            final var rolesObject = claims.get(ROLES_CLAIM, Collection.class);
            if (rolesObject == null) {
                throw new MissingClaimException(header, claims, "Missing \"roles\" claim");
            }
            // Check roles Collection contains only Strings (discard those that are not strings)
            final var roles = ((Collection<?>) rolesObject).stream()
                    .filter(role -> role instanceof String)
                    .collect(Collectors.toSet());
            claims.put(ROLES_CLAIM, roles); // Update the collection (which discarded non String values).

            // Check issued at date is present and it is not a future date
            final var issuedAt = Optional.ofNullable(claims.getIssuedAt())
                    .orElseThrow(() -> new MissingClaimException(header, claims, "Missing \"issued at\" date"));
            if (issuedAt.after(new Date())) {
                throw new MalformedJwtException("The \"issued at\" date is a future date");
            }
            // Check expiration date is not missing
            if (claims.getExpiration() == null) {
                throw new MissingClaimException(header, claims, "Missing \"expiration\" date");
            }

            return jws;
        }
    }
}
