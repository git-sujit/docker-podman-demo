package com.dummy.uba.ubair.service;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class IrService {
    private final WebClient webClient;
    private final String EVENTS_SERVICE_BASE_URL = "http://uba-events:8002";
    private final String TRIGGER_IR_END_POINT = "/events/ir/trigger";

    public IrService(WebClient.Builder builder) {
        webClient = builder.baseUrl(EVENTS_SERVICE_BASE_URL).build();
    }

    public void triggerIr() {
        webClient
                .put()
                .uri(TRIGGER_IR_END_POINT)
                .retrieve()
                .bodyToMono(Void.class)
                .block();
    }
}
