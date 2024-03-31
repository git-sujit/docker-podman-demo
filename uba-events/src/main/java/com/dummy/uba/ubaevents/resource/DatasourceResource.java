package com.dummy.uba.ubaevents.resource;

import com.dummy.uba.ubaevents.entity.Datasource;
import com.dummy.uba.ubaevents.service.DatasourceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
public class DatasourceResource {
    private static final Logger LOGGER = LoggerFactory.getLogger(DatasourceResource.class);

    @Autowired
    private DatasourceService datasourceService;

    @PostMapping(value = "/datasources")
    public Datasource createDatasource(@RequestBody Datasource datasource) {
        LOGGER.debug("Creating a new Datasource: " + datasource);
        return datasourceService.createDatasource(datasource);
    }

    @GetMapping(value = "/datasources/{datasourceId}")
    public Datasource getDatasourceDetails(@PathVariable(value = "datasourceId", required = true) Long datasourceId) {
        LOGGER.debug("Getting Datasource details for datasourceId: " + datasourceId);
        Optional<Datasource> datasource = datasourceService.fetchDatasourceDetails(datasourceId);
        if (datasource == null || datasource.isEmpty()) {
            LOGGER.error("There is no datasource, with datasourceId = " + datasourceId);
        }
        return datasource.get();
    }

    @GetMapping(value = "/datasources")
    public List<Datasource> getDatasourceList() {
        LOGGER.debug("Getting All Datasources");
        List<Datasource> datasourceList = datasourceService.fetchDatasourceList();
        if (datasourceList == null || datasourceList.size() == 0) {
            LOGGER.info("There are no datasources in UBA system");
            datasourceList = new ArrayList<>();
        }
        return datasourceList;
    }

    @GetMapping(value = "/test")
    public String isOkTested() {
        return "Ok Tested... UBA-Events";
    }
}
