package com.novawaf.config;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import com.novawaf.domain.WafLog;

public interface WafLogRepository extends JpaRepository<WafLog, Long> {
    Page<WafLog> findByCategory(String category, Pageable pageable);
}
