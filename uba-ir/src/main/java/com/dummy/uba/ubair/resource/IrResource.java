package com.dummy.uba.ubair.resource;

import com.dummy.uba.ubair.service.IrService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IrResource {
    @Autowired
    private IrService irService;

    @PutMapping(value = "/ir/process")
    public void processEtl() {
        irService.triggerIr();
    }

    @GetMapping(value = "/test")
    public String isOkTested() {
        return "Ok Tested... UBA-IR";
    }
}
