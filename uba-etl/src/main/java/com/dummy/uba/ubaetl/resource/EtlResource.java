package com.dummy.uba.ubaetl.resource;

import com.dummy.uba.ubaetl.service.EtlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EtlResource {

    @Autowired
    private EtlService etlService;

    @PutMapping(value = "/etl/process")
    public void processEtl() {
        etlService.triggerEtl();
    }

    @GetMapping(value = "/test")
    public String isOkTested() {
        return "Ok Tested... UBA-ETL";
    }
}
