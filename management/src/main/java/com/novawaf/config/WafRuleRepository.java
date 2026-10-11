package com.novawaf.config;

import org.springframework.data.jpa.repository.JpaRepository;
import com.novawaf.domain.WafRule;
import java.util.List;

public interface WafRuleRepository extends JpaRepository<WafRule, Long> {
    List<WafRule> findByEnabledTrue();
}
