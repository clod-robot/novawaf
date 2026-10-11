package com.novawaf.service;

import com.novawaf.domain.WafLog;
import com.novawaf.config.WafLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class LogService {

    @Autowired
    private WafLogRepository repo;

    public Page<WafLog> list(int page, int size, String category) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        if (category != null && !category.isEmpty()) {
            return repo.findByCategory(category, pr);
        }
        return repo.findAll(pr);
    }
}
