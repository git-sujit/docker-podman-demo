package com.dummy.uba.ubaevents.entity;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Entity
@Table(indexes = {
        @Index(name = "etl_index", columnList = "isETLProcessed"),
        @Index(name = "ir_index", columnList = "isIRProcessed")
})
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(of = {"eventId",})
@SequenceGenerator(name = "event_id_gen", sequenceName = "event_id_gen", initialValue = 10000)
public class Event extends BaseEntity<Event> {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "event_id_gen")
    private Long eventId;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "datasourceId", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Datasource datasource;

    private String data;

    private boolean isETLProcessed;

    private boolean isIRProcessed;

    public Event withETLProcessed(boolean isEtlProcessed) {
        this.isETLProcessed = isEtlProcessed;
        return this;
    }

    public Event withIRProcessed(boolean isIRProcessed) {
        this.isIRProcessed = isIRProcessed;
        return this;
    }
}
