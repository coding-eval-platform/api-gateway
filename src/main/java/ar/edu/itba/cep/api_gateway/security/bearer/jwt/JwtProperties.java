package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Properties for configuring encoding/decoding of JWT tokens.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "authentication.jwt")
/* package */  class JwtProperties {

    /**
     * The internal tokens properties.
     */
    @NestedConfigurationProperty
    private InternalTokensProperties internal;
    /**
     * The external tokens properties.
     */
    @NestedConfigurationProperty
    private ExternalTokensProperties external;


    /**
     * The internal tokens properties.
     */
    @Getter
    @Setter
    /* package */ static final class InternalTokensProperties {

        /**
         * The private key used to sign internal tokens.
         */
        private String privateKey;
    }

    /**
     * The external tokens properties.
     */
    @Getter
    @Setter
    /* package */ static final class ExternalTokensProperties {

        /**
         * The public key used to verify external tokens.
         */
        private String publicKey;
    }
}
