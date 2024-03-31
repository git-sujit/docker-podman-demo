package com.dummy.uba.ubaevents.jpa;

import com.dummy.uba.ubaevents.entity.Datasource;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DatasourceRepository extends JpaRepository<Datasource, Long> {
}
