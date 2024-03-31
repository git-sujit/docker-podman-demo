package com.dummy.uba.ubaevents.entity;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(of = {"datasourceId", "datasourceName", "type", "format"})
@SequenceGenerator(name = "datasource_id_gen", sequenceName = "datasource_id_gen", initialValue = 6000)
public class Datasource extends BaseEntity<Datasource> {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "datasource_id_gen")
    private Long datasourceId;

    private String datasourceName;
    private String type;
    private String format;

    //@OneToMany(mappedBy = "datasource")
    //private Set<Event> events;
}
