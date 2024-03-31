package com.dummy.uba.ubaaccounts.resource;

import com.dummy.uba.ubaaccounts.entity.Account;
import com.dummy.uba.ubaaccounts.service.AccountService;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class AccountsResource {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccountsResource.class);

    @Autowired
    private AccountService accountService;

    @PostMapping(value = "/accounts")
    public Account createAccount(@RequestBody Account account) {
        LOGGER.debug("Creating a new Account: " + account);
        return accountService.createAccount(account);
    }

    @GetMapping(value = "/accounts/{accountId}")
    public Account getAccountDetails(@PathVariable(value = "accountId", required = true) Long accountId) {
        LOGGER.debug("Getting Account details for AccountId: " + accountId);
        Optional<Account> account = accountService.fetchAccountDetails(accountId);
        if (account == null || account.isEmpty()) {
            LOGGER.error("There is no account, with accountId = " + accountId);
            throw new EntityNotFoundException("There is no account, with accountId = " + accountId);
        }
        return account.get();
    }

    @GetMapping(value = "/accounts")
    public List<Account> getAccountList() {
        LOGGER.debug("Getting All Accounts");
        List<Account> accountList = accountService.fetchAccountList();
        if (accountList == null || accountList.size() == 0) {
            LOGGER.info("There are no Accounts in UBA system");
            throw new EntityNotFoundException("There are no Accounts in UBA system");
        }
        return accountList;
    }

    @GetMapping(value = "/test")
    public String isOkTested() {
        return "Ok Tested... UBA-Accounts";
    }
}
