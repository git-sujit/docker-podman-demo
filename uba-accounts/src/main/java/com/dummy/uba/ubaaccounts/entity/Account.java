package com.dummy.uba.ubaaccounts.entity;

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
@EqualsAndHashCode(of = {"accountId", "accountName"})
@SequenceGenerator(name = "account_id_gen", sequenceName = "account_id_gen", initialValue = 5000)
public class Account extends BaseEntity<Account> {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "account_id_gen")
    private Long accountId;

    private String accountName;
    private String email;
    private String mobile;
}
