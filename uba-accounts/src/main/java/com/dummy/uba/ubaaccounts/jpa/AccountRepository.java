package com.dummy.uba.ubaaccounts.jpa;

import com.dummy.uba.ubaaccounts.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, Long> {

}
