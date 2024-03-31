package com.dummy.uba.ubaevents.service;

import com.dummy.uba.ubaevents.entity.Event;
import com.dummy.uba.ubaevents.jpa.EventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class EventService {
    @Autowired
    private EventRepository eventRepository;

    public Event createEvent(Event event) {
        return eventRepository.save(event
                .withETLProcessed(false)
                .withIRProcessed(false)
                .withCreatedDate(ZonedDateTime.now())
                .withModifiedDate(ZonedDateTime.now())
                .withCreatedBy("SYSTEM")
                .withModifiedBy("SYSTEM")
                .withVersion(1L));
    }

    public Event updateEvent(Event event) {
        return eventRepository.save(event);
    }

    public Optional<Event> fetchEventDetails(Long eventId) {
        return eventRepository.findById(eventId);
    }

    public List<Event> fetchEventList() {
        return eventRepository.findAll();
    }

    public List<Event> fetchEventsForETL() {
        return eventRepository.fetchEventsForETLProcessing();
    }

    public List<Event> fetchEventsForIR() {
        return eventRepository.fetchEventsForIRProcessing();
    }

}
