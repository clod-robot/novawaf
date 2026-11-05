package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiGuardConfig;
import org.apache.ibatis.annotations.*;

/** API 防护全局配置单行读写（表 waf_api_guard_config，固定 id=1）。 */
@Mapper
public interface ApiGuardConfigMapper {

    String COLS = "id, enabled, stage, token_enabled AS tokenEnabled, token_enforce AS tokenEnforce, " +
            "token_mode AS tokenMode, token_alg AS tokenAlg, token_secret AS tokenSecret, " +
            "token_max_age AS tokenMaxAge, token_require_iat AS tokenRequireIat, " +
            "token_reuse_window AS tokenReuseWindow, token_reuse_max_ips AS tokenReuseMaxIps, " +
            "token_enforce_reuse AS tokenEnforceReuse, dlp_enabled AS dlpEnabled, dlp_action AS dlpAction, " +
            "dlp_max_bytes AS dlpMaxBytes, update_time ";

    @Select("SELECT " + COLS + "FROM waf_api_guard_config WHERE id = 1")
    ApiGuardConfig selectSingleton();

    @Insert("INSERT INTO waf_api_guard_config(id, enabled, stage, token_enabled, token_enforce, token_mode, " +
            "token_alg, token_secret, token_max_age, token_require_iat, token_reuse_window, token_reuse_max_ips, " +
            "token_enforce_reuse, dlp_enabled, dlp_action, dlp_max_bytes) VALUES(1, #{enabled}, #{stage}, " +
            "#{tokenEnabled}, #{tokenEnforce}, #{tokenMode}, #{tokenAlg}, #{tokenSecret}, #{tokenMaxAge}, " +
            "#{tokenRequireIat}, #{tokenReuseWindow}, #{tokenReuseMaxIps}, #{tokenEnforceReuse}, " +
            "#{dlpEnabled}, #{dlpAction}, #{dlpMaxBytes})")
    int insertSingleton(ApiGuardConfig c);

    @Update("UPDATE waf_api_guard_config SET enabled=#{enabled}, stage=#{stage}, token_enabled=#{tokenEnabled}, " +
            "token_enforce=#{tokenEnforce}, token_mode=#{tokenMode}, token_alg=#{tokenAlg}, token_secret=#{tokenSecret}, " +
            "token_max_age=#{tokenMaxAge}, token_require_iat=#{tokenRequireIat}, " +
            "token_reuse_window=#{tokenReuseWindow}, token_reuse_max_ips=#{tokenReuseMaxIps}, " +
            "token_enforce_reuse=#{tokenEnforceReuse}, dlp_enabled=#{dlpEnabled}, dlp_action=#{dlpAction}, " +
            "dlp_max_bytes=#{dlpMaxBytes}, update_time=NOW() WHERE id = 1")
    int updateSingleton(ApiGuardConfig c);
}
