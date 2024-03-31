package com.dummy.uba.ubaetl.service;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class EtlService {
    private final WebClient webClient;
    private final String EVENTS_SERVICE_BASE_URL = "http://uba-events:8002";
    private final String TRIGGER_ETL_END_POINT = "/events/etl/trigger";

    public EtlService(WebClient.Builder builder) {
        webClient = builder.baseUrl(EVENTS_SERVICE_BASE_URL).build();
    }

    public void triggerEtl() {
        webClient
                .put()
                .uri(TRIGGER_ETL_END_POINT)
                .retrieve()
                .bodyToMono(Void.class)
                .block();
    }
}
