package com.dummy.uba.ubaevents.resource;

import com.dummy.uba.ubaevents.entity.Event;
import com.dummy.uba.ubaevents.service.EventService;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class EventResource {
    private static final Logger LOGGER = LoggerFactory.getLogger(EventResource.class);

    @Autowired
    private EventService eventService;

    @PostMapping(value = "/events")
    public Event createEvent(@RequestBody Event event) {
        LOGGER.debug("Creating a new Event: " + event);
        return eventService.createEvent(event);
    }

    @GetMapping(value = "/events/{eventId}")
    public Event getEventDetails(@PathVariable(value = "eventId", required = true) Long eventId) {
        LOGGER.debug("Getting Event details for eventId: " + eventId);
        Optional<Event> event = eventService.fetchEventDetails(eventId);
        if (event == null || event.isEmpty()) {
            LOGGER.error("There is no event, with eventId = " + eventId);
            throw new EntityNotFoundException("There is no event, with eventId = " + eventId);
        }
        return event.get();
    }

    @GetMapping(value = "/events")
    public List<Event> getEventList() {
        LOGGER.debug("Getting All Events");
        List<Event> eventList = eventService.fetchEventList();
        if (eventList == null || eventList.size() == 0) {
            LOGGER.info("There are no Events in UBA system");
            throw new EntityNotFoundException("There are no Events in UBA system");
        }
        return eventList;
    }

    @GetMapping(value = "/events/etl")
    public List<Event> getEventsForETL() {
        LOGGER.debug("Getting All Events to be processed by ETL");
        List<Event> eventList = eventService.fetchEventsForETL();

        if (eventList == null || eventList.size() == 0) {
            LOGGER.info("There are no Events to be processed by ETL in UBA system");
            throw new EntityNotFoundException("There are no Events to be processed by ETL in UBA system");
        }
        return eventList;
    }

    @GetMapping(value = "/events/ir")
    public List<Event> getEventsForIR() {
        LOGGER.debug("Getting All Events to be processed by IR");
        List<Event> eventList = eventService.fetchEventsForIR();
        if (eventList == null || eventList.size() == 0) {
            LOGGER.info("There are no Events to be processed by IR in UBA system");
            throw new EntityNotFoundException("There are no Events to be processed by IR in UBA system");
        }
        return eventList;
    }

    @PutMapping(value = "/events/etl/trigger")
    public void triggerEtl() {
        List<Event> eventList = getEventsForETL();
        for (Event event : eventList) {
            eventService.updateEvent(event.withETLProcessed(true));
        }
    }

    @PutMapping(value = "/events/ir/trigger")
    public void triggerIr() {
        List<Event> eventList = getEventsForIR();
        for (Event event : eventList) {
            eventService.updateEvent(event.withIRProcessed(true));
        }
    }

    @PutMapping(value = "/events/etl")
    public Event processEventETL(@RequestBody Event event) {
        LOGGER.debug("ETL-Processing of Event, eventId: " + event.getEventId());
        Event fetchedEvent = getEventDetails(event.getEventId());
        return eventService.updateEvent(fetchedEvent.withETLProcessed(true));
    }

    @PutMapping(value = "/events/ir")
    public Event processEventIR(@RequestBody Event event) {
        LOGGER.debug("IR-Processing of Event, eventId: " + event.getEventId());
        Event fetchedEvent = getEventDetails(event.getEventId());
        return eventService.updateEvent(fetchedEvent.withIRProcessed(true));
    }
}
