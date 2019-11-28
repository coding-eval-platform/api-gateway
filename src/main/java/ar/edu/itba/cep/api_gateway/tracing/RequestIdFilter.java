package ar.edu.itba.cep.api_gateway.tracing;

import brave.Span;
import brave.Tracer;
import brave.propagation.TraceContext;
import lombok.AllArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Filter in charge of setting the request id in a response header.
 * The tracing id given by sleuth will be used as request id.
 */
@Component
@AllArgsConstructor
public class RequestIdFilter implements GlobalFilter {

    /**
     * The header in which the request id will be reported.
     */
    public static final String REQUEST_ID_HEADER = "X-Request-Id";


    /**
     * The {@link Tracer} used to get the tracing id (which will be used as request id).
     */
    private final Tracer tracer;


    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        return chain.filter(exchange)
                .then(Mono.fromRunnable(
                        () -> Optional.ofNullable(tracer.currentSpan())
                                .map(Span::context)
                                .map(TraceContext::traceIdString)
                                .ifPresent(id -> exchange.getResponse().getHeaders().add(REQUEST_ID_HEADER, id))
                        )
                );
    }
}
