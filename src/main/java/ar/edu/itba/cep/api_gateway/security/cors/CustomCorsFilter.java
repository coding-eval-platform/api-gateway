package ar.edu.itba.cep.api_gateway.security.cors;


import org.springframework.web.cors.reactive.CorsWebFilter;

/**
 * A custom {@link CorsWebFilter} that uses a custom Cor
 */
public class CustomCorsFilter extends CorsWebFilter {

    /**
     * Constructor.
     *
     * @param configSource The {@link EverythingAllowedCorsConfigurationSource} from where CORS config data is taken.
     * @param processor    The {@link CustomCorsProcessor} that will handle CORS requests.
     */
    public CustomCorsFilter(
            final EverythingAllowedCorsConfigurationSource configSource,
            final CustomCorsProcessor processor) {
        super(configSource, processor);
    }
}
