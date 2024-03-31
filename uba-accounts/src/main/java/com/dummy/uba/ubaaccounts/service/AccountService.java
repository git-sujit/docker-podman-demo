package com.dummy.uba.ubaaccounts.service;

import com.dummy.uba.ubaaccounts.entity.Account;
import com.dummy.uba.ubaaccounts.jpa.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class AccountService {
    @Autowired
    private AccountRepository accountRepository;

    public Account createAccount(Account account) {
        return accountRepository.save(account.withCreatedDate(ZonedDateTime.now())
                .withModifiedDate(ZonedDateTime.now())
                .withCreatedBy("SYSTEM")
                .withModifiedBy("SYSTEM")
                .withVersion(1L));
    }

    public Optional<Account> fetchAccountDetails(Long accountId) {
        return accountRepository.findById(accountId);
    }

    public List<Account> fetchAccountList() {
        return accountRepository.findAll();
    }
}
