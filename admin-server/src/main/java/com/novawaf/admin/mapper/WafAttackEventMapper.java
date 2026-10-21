package com.novawaf.admin.mapper;

import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Map;

/**
 * 攻击事件归档表(引擎实时事件经 Redis 归档队列持久化到 MySQL):
 * 支撑任意 IP、任意时段的完整攻击链回看, 不受 Redis 环形窗口/分桶 TTL 限制。
 */
@Mapper
public interface WafAttackEventMapper {

    /** 批量写入(INSERT IGNORE 去重: dedup 唯一键防消费崩溃重试导致的重复) */
    @Insert("<script>INSERT IGNORE INTO waf_attack_event(ts,ip,action,category,rule_id,matched,severity,dedup) VALUES "
            + "<foreach collection='rows' item='r' separator=','>"
            + "(#{r.ts},#{r.ip},#{r.action},#{r.category},#{r.ruleId},#{r.matched},#{r.severity},#{r.dedup})"
            + "</foreach></script>")
    int insertBatch(@Param("rows") List<Map<String, Object>> rows);

    /** 按 IP + 时段查完整时间线(ts 升序) */
    @Select("<script>SELECT ts,ip,action,category,rule_id AS ruleId,matched,severity FROM waf_attack_event "
            + "WHERE ip=#{ip} "
            + "<if test='from!=null'> AND ts&gt;=#{from} </if>"
            + "<if test='to!=null'> AND ts&lt;=#{to} </if>"
            + "ORDER BY ts ASC LIMIT #{limit}</script>")
    List<Map<String, Object>> selectByIp(@Param("ip") String ip, @Param("from") Long from,
                                         @Param("to") Long to, @Param("limit") int limit);

    /** 该 IP 归档总条数(用于提示实际归档规模) */
    @Select("SELECT COUNT(*) FROM waf_attack_event WHERE ip=#{ip}")
    long countByIp(@Param("ip") String ip);

    /** 清理过期归档(保留期外数据, 每日定时执行) */
    @Delete("DELETE FROM waf_attack_event WHERE ts < #{beforeTs}")
    int deleteBefore(@Param("beforeTs") long beforeTs);
}
