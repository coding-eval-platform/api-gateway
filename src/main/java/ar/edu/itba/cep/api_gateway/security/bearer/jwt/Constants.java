package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Class containing constants to be used by the JWT module.
 */
/* package */ class Constants {

    /**
     * Private constructor to avoid instantiation.
     */
    private Constants() {
    }

    /**
     * Claims name for the roles in a JWT.
     */
    /* package */ static final String ROLES_CLAIM = "roles";

    /**
     * Signature algorithm used to sign JWT tokens.
     */
    /* package */ static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.RS512;
}
