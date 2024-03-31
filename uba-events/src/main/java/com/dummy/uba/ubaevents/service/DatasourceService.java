package com.dummy.uba.ubaevents.service;

import com.dummy.uba.ubaevents.entity.Datasource;
import com.dummy.uba.ubaevents.jpa.DatasourceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class DatasourceService {
    @Autowired
    private DatasourceRepository datasourceRepository;

    public Datasource createDatasource(Datasource datasource) {
        return datasourceRepository.save(datasource.withCreatedDate(ZonedDateTime.now())
                .withModifiedDate(ZonedDateTime.now())
                .withCreatedBy("SYSTEM")
                .withModifiedBy("SYSTEM")
                .withVersion(1L));
    }

    public Optional<Datasource> fetchDatasourceDetails(Long datasourceId) {
        return datasourceRepository.findById(datasourceId);
    }

    public List<Datasource> fetchDatasourceList() {
        return datasourceRepository.findAll();
    }

}
