package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.AgenticConfig;
import org.apache.ibatis.annotations.*;

/** Agentic AI 引擎配置单行读写（表 waf_agentic_config，固定 id=1）。 */
@Mapper
public interface AgenticConfigMapper {

    String COLS = "id, enabled, block, threshold, max_steps AS maxSteps, budget_per_min AS budgetPerMin, " +
            "cache_ttl_sec AS cacheTtlSec, trace_max AS traceMax, llm_enabled AS llmEnabled, " +
            "llm_endpoint AS llmEndpoint, llm_api_key AS llmApiKey, llm_model AS llmModel, " +
            "llm_timeout_ms AS llmTimeoutMs, llm_max_retries AS llmMaxRetries, llm_max_tokens AS llmMaxTokens, update_time ";

    @Select("SELECT " + COLS + "FROM waf_agentic_config WHERE id = 1")
    AgenticConfig selectSingleton();

    @Insert("INSERT INTO waf_agentic_config(id, enabled, block, threshold, max_steps, budget_per_min, cache_ttl_sec, " +
            "trace_max, llm_enabled, llm_endpoint, llm_api_key, llm_model, llm_timeout_ms, llm_max_retries, llm_max_tokens) " +
            "VALUES(1, #{enabled}, #{block}, #{threshold}, #{maxSteps}, #{budgetPerMin}, #{cacheTtlSec}, #{traceMax}, " +
            "#{llmEnabled}, #{llmEndpoint}, #{llmApiKey}, #{llmModel}, #{llmTimeoutMs}, #{llmMaxRetries}, #{llmMaxTokens})")
    int insertSingleton(AgenticConfig c);

    @Update("UPDATE waf_agentic_config SET enabled=#{enabled}, block=#{block}, threshold=#{threshold}, " +
            "max_steps=#{maxSteps}, budget_per_min=#{budgetPerMin}, cache_ttl_sec=#{cacheTtlSec}, trace_max=#{traceMax}, " +
            "llm_enabled=#{llmEnabled}, llm_endpoint=#{llmEndpoint}, llm_api_key=#{llmApiKey}, llm_model=#{llmModel}, " +
            "llm_timeout_ms=#{llmTimeoutMs}, llm_max_retries=#{llmMaxRetries}, llm_max_tokens=#{llmMaxTokens}, " +
            "update_time=NOW() WHERE id = 1")
    int updateSingleton(AgenticConfig c);
}
