package com.dummy.uba.ubaevents.jpa;

import com.dummy.uba.ubaevents.entity.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {
    @Query(value = "SELECT t FROM Event t WHERE t.isETLProcessed=false")
    List<Event> fetchEventsForETLProcessing();

    @Query(value = "SELECT t FROM Event t WHERE t.isIRProcessed=false")
    List<Event> fetchEventsForIRProcessing();

}
