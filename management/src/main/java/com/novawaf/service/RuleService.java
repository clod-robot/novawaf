package com.novawaf.service;

import com.novawaf.domain.WafRule;
import com.novawaf.config.WafRuleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class RuleService {

    @Autowired
    private WafRuleRepository repo;

    @Value("${novawaf.engine.url:http://127.0.0.1:8080}")
    private String engineUrl;

    public List<WafRule> listAll() {
        return repo.findAll();
    }

    public WafRule save(WafRule rule) {
        return repo.save(rule);
    }

    public void delete(Long id) {
        repo.deleteById(id);
    }

    /** 将全量规则推送到 C++ 检测引擎（热加载，不重启） */
    public boolean pushToEngine() {
        try {
            List<WafRule> rules = repo.findByEnabledTrue();
            RestTemplate rt = new RestTemplate();
            rt.postForObject(engineUrl + "/reload", rules, String.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
