package com.dummy.uba.ubaaccounts.entity;

import jakarta.persistence.MappedSuperclass;
import lombok.Getter;

import java.time.ZonedDateTime;

@MappedSuperclass
@Getter
public class BaseEntity<T> {
    private ZonedDateTime createdDate;
    private ZonedDateTime modifiedDate;
    private String createdBy;
    private String modifiedBy;
    private Long version;

    public T withCreatedDate(ZonedDateTime createdDate) {
        this.createdDate = createdDate;
        return (T) this;
    }

    public T withModifiedDate(ZonedDateTime modifiedDate) {
        this.modifiedDate = modifiedDate;
        return (T) this;
    }

    public T withCreatedBy(String createdBy) {
        this.createdBy = createdBy;
        return (T) this;
    }

    public T withModifiedBy(String modifiedBy) {
        this.modifiedBy = modifiedBy;
        return (T) this;
    }

    public T withVersion(Long version) {
        this.version = version;
        return (T) this;
    }
}
