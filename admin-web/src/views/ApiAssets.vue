<template>
  <div class="mecha-panel p">
    <el-tabs v-model="tab" type="border-card" class="api-tabs">
      <!-- ========================= 1. 资产目录 ========================= -->
      <el-tab-pane label="资产目录" name="dir">
        <div class="stat-row">
          <div class="stat"><span class="k">已发现 API</span><b class="v">{{ sum.total }}</b></div>
          <div class="stat warn"><span class="k">影子 API（未登记）</span><b class="v">{{ sum.shadow }}</b></div>
          <div class="stat bad"><span class="k">僵尸 API</span><b class="v">{{ sum.zombie }}</b></div>
          <div class="stat ok"><span class="k">已登记</span><b class="v">{{ sum.registered }}</b></div>
          <div class="stat"><span class="k">24h 新增</span><b class="v">{{ sum.new24h }}</b></div>
          <div class="stat"><span class="k">清单条目</span><b class="v">{{ sum.inventory }}</b></div>
        </div>
        <div class="filter-bar">
          <el-select v-model="f.kind" size="small" clearable placeholder="资产状态" class="f-sel">
            <el-option label="影子（未登记）" value="shadow" />
            <el-option label="僵尸" value="zombie" />
            <el-option label="已登记" value="registered" />
          </el-select>
          <el-select v-model="f.appId" size="small" clearable placeholder="所属应用" class="f-sel">
            <el-option label="全部应用" value="" />
            <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
          </el-select>
          <el-select v-model="f.method" size="small" clearable placeholder="方法" class="f-sel-sm">
            <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
          </el-select>
          <el-input v-model="f.keyword" size="small" clearable placeholder="路径关键字" class="f-inp" />
          <span class="f-count">共 <b>{{ assets.length }}</b> 条（最多展示 1000 条，请用筛选缩小范围）</span>
          <span style="flex:1"></span>
          <el-button size="small" @click="resetFilter">重置</el-button>
          <el-button size="small" @click="loadAssets">刷新</el-button>
          <el-button size="small" type="primary" :disabled="!riskCount" @click="promoteFiltered">
            一键登记当前筛选（{{ riskCount }}）
          </el-button>
        </div>
        <DataTable :data="assets" :columns="assetCols" :header-search="false" :loading="loading"
                   height="calc(100vh - 372px)">
          <template #cell-kind="{ row }">
            <el-tag :type="kindTag(row.kind)" size="small" effect="dark">{{ kindText(row.kind) }}</el-tag>
          </template>
          <template #cell-appName="{ row }">
            <el-tag :type="row.appId ? 'primary' : 'info'" size="small" effect="plain">{{ row.appName }}</el-tag>
          </template>
          <template #cell-template="{ row }"><code>{{ row.template }}</code></template>
          <template #cell-auth="{ row }">
            <span :class="row.auth === '1' ? 'ok' : 'bad'">{{ row.auth === '1' ? '有' : '无' }}</span>
          </template>
          <template #cell-sensitive="{ row }">
            <el-tag v-if="row.sensitive" type="danger" size="small">敏感</el-tag>
            <span v-else class="muted">-</span>
          </template>
          <template #cell-status="{ row }">{{ fmtStatus(row.status) }}</template>
          <template #cell-count="{ row }"><span class="num">{{ fmtNum(row.count) }}</span></template>
          <template #cell-errCount="{ row }">
            <span class="num" :class="row.errCount ? 'bad' : ''">{{ fmtNum(row.errCount) }}</span>
          </template>
          <template #cell-lastSeen="{ row }">{{ row.lastSeen ? fmt(row.lastSeen) : '无流量' }}</template>
          <template #cell-op="{ row }">
            <el-button size="small" type="primary" link
                       :disabled="row.kind === 'registered'" @click="promoteOne(row)">登记</el-button>
          </template>
        </DataTable>
      </el-tab-pane>

      <!-- ========================= 2. 登记清单 ========================= -->
      <el-tab-pane label="登记清单" name="inv">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom:10px"
          title="已登记清单是引擎判定影子/僵尸 API 的唯一依据。"
          description="保存后自动整表发布到引擎（Redis + 版本号），约 5 秒内生效。ANY 发布时会自动展开为 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS 七个方法；路径需使用引擎归一后的模板（可变段用 {id} 表示）。" />
        <div class="filter-bar">
          <el-input v-model="invKw" size="small" clearable placeholder="搜索路径/名称/责任人" class="f-inp-lg" />
          <span class="f-count">共 <b>{{ invFiltered.length }}</b> 条</span>
          <span style="flex:1"></span>
          <el-button size="small" @click="loadInventory">刷新</el-button>
          <el-button size="small" @click="openImport">批量导入</el-button>
          <el-button size="small" type="primary" @click="openInvCreate">+ 登记资产</el-button>
        </div>
        <DataTable :data="invFiltered" :columns="invCols" :header-search="false"
                   height="calc(100vh - 330px)">
          <template #cell-appName="{ row }">
            <el-tag :type="row.appId ? 'primary' : 'info'" size="small" effect="plain">{{ row.appName }}</el-tag>
          </template>
          <template #cell-path="{ row }"><code>{{ row.path }}</code></template>
          <template #cell-enabled="{ row }">
            <el-tag :type="row.enabled === true ? 'success' : 'info'" size="small">
              {{ row.enabled === true ? '启用' : '禁用' }}
            </el-tag>
          </template>
          <template #cell-updateTime="{ row }">{{ fmt(row.updateTime || row.createTime) }}</template>
          <template #cell-op="{ row }">
            <el-button size="small" type="primary" link @click="openInvEdit(row)">编辑</el-button>
            <el-button size="small" :type="row.enabled === true ? 'warning' : 'success'" link @click="toggleInv(row)">
              {{ row.enabled === true ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" link @click="delInv(row)">删除</el-button>
          </template>
        </DataTable>
      </el-tab-pane>

      <!-- ========================= 3. API 策略 ========================= -->
      <el-tab-pane label="API 策略" name="guard">
        <div class="sub-title">全局防护配置（保存即发布，引擎 5 秒内生效）</div>
        <el-form :model="cfg" label-width="132px" class="cfg-form">
          <div class="cfg-grid">
            <el-form-item label="限流总开关"><el-switch v-model="cfg.enabled" /></el-form-item>
            <el-form-item label="生效阶段">
              <el-radio-group v-model="cfg.stage">
                <el-radio value="monitor">观察期（只记录）</el-radio>
                <el-radio value="enforce">正式生效</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="Token 校验开关"><el-switch v-model="cfg.tokenEnabled" /></el-form-item>
            <el-form-item label="非法令牌严格拒绝">
              <el-switch v-model="cfg.tokenEnforce" />
              <span class="hint">关闭=灰度，仅记录不拦截</span>
            </el-form-item>
            <el-form-item label="令牌模式">
              <el-select v-model="cfg.tokenMode" style="width:160px">
                <el-option label="JWT" value="jwt" />
                <el-option label="不透明令牌" value="opaque" />
                <el-option label="任意（两种都接受）" value="any" />
              </el-select>
            </el-form-item>
            <el-form-item label="允许算法">
              <el-input v-model="cfg.tokenAlg" placeholder="HS256,RS256" style="width:200px" />
            </el-form-item>
            <el-form-item label="JWT 签名密钥">
              <el-input v-model="cfg.tokenSecret" type="password" show-password
                        placeholder="留空=不校验签名，仅校验结构与时效" />
            </el-form-item>
            <el-form-item label="令牌最大有效期">
              <el-input-number v-model="cfg.tokenMaxAge" :min="60" :max="31536000" :step="3600" />
              <span class="hint">秒</span>
            </el-form-item>
            <el-form-item label="强制 iat"><el-switch v-model="cfg.tokenRequireIat" /></el-form-item>
            <el-form-item label="复用检测窗口">
              <el-input-number v-model="cfg.tokenReuseWindow" :min="0" :max="86400" :step="10" />
              <span class="hint">秒</span>
            </el-form-item>
            <el-form-item label="窗口最大来源 IP">
              <el-input-number v-model="cfg.tokenReuseMaxIps" :min="1" :max="1000" />
            </el-form-item>
            <el-form-item label="复用异常直接拒绝"><el-switch v-model="cfg.tokenEnforceReuse" /></el-form-item>
            <el-form-item label="响应脱敏开关"><el-switch v-model="cfg.dlpEnabled" /></el-form-item>
            <el-form-item label="脱敏动作">
              <el-radio-group v-model="cfg.dlpAction">
                <el-radio value="mask">脱敏</el-radio>
                <el-radio value="log">仅记录</el-radio>
                <el-radio value="block">拦截响应</el-radio>
                <el-radio value="off">关闭</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="脱敏体上限">
              <el-input-number v-model="cfg.dlpMaxBytes" :min="1024" :max="16777216" :step="1024" />
              <span class="hint">字节</span>
            </el-form-item>
          </div>
          <div class="cfg-actions">
            <el-button type="primary" :loading="savingCfg" @click="saveCfg">保存并发布</el-button>
          </div>
        </el-form>

        <div class="sub-title">API 级别限流策略
          <el-button size="small" type="primary" style="margin-left:10px" @click="openRuleCreate">+ 新增策略</el-button>
        </div>
        <DataTable :data="rules" :columns="ruleCols" :header-search="false"
                   height="calc(100vh - 560px)" :page-size="20" :page-sizes="[20, 50, 100]">
          <template #cell-appName="{ row }">
            <el-tag :type="row.appId ? 'primary' : 'info'" size="small" effect="plain">{{ row.appName }}</el-tag>
          </template>
          <template #cell-path="{ row }"><code>{{ row.path }}</code></template>
          <template #cell-scope="{ row }">{{ scopeText(row.scope) }}</template>
          <template #cell-action="{ row }">
            <el-tag :type="row.action === 'ban' ? 'danger' : row.action === '429' ? 'warning' : 'info'" size="small">
              {{ actionText(row.action) }}
            </el-tag>
          </template>
          <template #cell-tokenRequired="{ row }">
            <el-tag v-if="row.tokenRequired" type="success" size="small">必需</el-tag>
            <span v-else class="muted">-</span>
          </template>
          <template #cell-enabled="{ row }">
            <el-tag :type="row.enabled === true ? 'success' : 'info'" size="small">
              {{ row.enabled === true ? '启用' : '禁用' }}
            </el-tag>
          </template>
          <template #cell-op="{ row }">
            <el-button size="small" type="primary" link @click="openRuleEdit(row)">编辑</el-button>
            <el-button size="small" :type="row.enabled === true ? 'warning' : 'success'" link @click="toggleRule(row)">
              {{ row.enabled === true ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" link @click="delRule(row)">删除</el-button>
          </template>
        </DataTable>

        <div class="sub-title">不透明令牌白名单
          <el-button size="small" type="primary" style="margin-left:10px" @click="openTokenCreate">+ 新增令牌</el-button>
        </div>
        <DataTable :data="tokens" :columns="tokenCols" :header-search="false"
                   height="260px" :page-size="20" :page-sizes="[20, 50, 100]">
          <template #cell-appName="{ row }">
            <el-tag :type="row.appId ? 'primary' : 'info'" size="small" effect="plain">{{ row.appName }}</el-tag>
          </template>
          <template #cell-tokenMask="{ row }"><code>{{ row.tokenMask }}</code></template>
          <template #cell-expireTime="{ row }">{{ row.expireTime ? fmt(row.expireTime) : '永久' }}</template>
          <template #cell-enabled="{ row }">
            <el-tag :type="row.enabled === true ? 'success' : 'info'" size="small">
              {{ row.enabled === true ? '启用' : '禁用' }}
            </el-tag>
          </template>
          <template #cell-op="{ row }">
            <el-button size="small" type="primary" link @click="openTokenEdit(row)">编辑</el-button>
            <el-button size="small" :type="row.enabled === true ? 'warning' : 'success'" link @click="toggleToken(row)">
              {{ row.enabled === true ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" link @click="delToken(row)">删除</el-button>
          </template>
        </DataTable>
      </el-tab-pane>

      <!-- ========================= 4. Agentic AI ========================= -->
      <el-tab-pane label="Agentic AI" name="agentic">
        <el-alert type="success" :closable="false" show-icon style="margin-bottom:10px"
          title="Agentic AI 引擎：代理循环（取证 → 反思 → 大模型研判）识别未知 API 威胁。"
          description="确定性取证工具先计算证据分（编码层数、危险语法族、参数偏离、载荷熵、影子路径、令牌异常等），证据分达到阈值才调用大模型，并由预算限流与熔断保护成本；判定结果进入威胁索引，后续同类请求可直接同步拦截。轨迹全程可审计。" />
        <el-form :model="ag" label-width="140px" class="cfg-form">
          <div class="cfg-grid">
            <el-form-item label="引擎开关"><el-switch v-model="ag.enabled" /></el-form-item>
            <el-form-item label="判定为攻击时拦截">
              <el-switch v-model="ag.block" />
              <span class="hint">关闭=仅告警</span>
            </el-form-item>
            <el-form-item label="判定阈值">
              <el-input-number v-model="ag.threshold" :min="0.1" :max="1" :step="0.05" :precision="2" />
            </el-form-item>
            <el-form-item label="代理循环步数">
              <el-input-number v-model="ag.maxSteps" :min="1" :max="10" />
            </el-form-item>
            <el-form-item label="每分钟调用预算">
              <el-input-number v-model="ag.budgetPerMin" :min="0" :max="2000" />
            </el-form-item>
            <el-form-item label="指纹缓存 TTL">
              <el-input-number v-model="ag.cacheTtlSec" :min="30" :max="86400" :step="30" />
              <span class="hint">秒</span>
            </el-form-item>
            <el-form-item label="轨迹保留条数">
              <el-input-number v-model="ag.traceMax" :min="100" :max="10000" :step="100" />
            </el-form-item>
            <el-form-item label="大模型接入"><el-switch v-model="ag.llmEnabled" /></el-form-item>
            <el-form-item label="模型接口地址">
              <el-input v-model="ag.llmEndpoint" placeholder="https://api.example.com/v1/chat/completions" />
            </el-form-item>
            <el-form-item label="API Key">
              <el-input v-model="ag.llmApiKey" type="password" show-password
                        :placeholder="ag.llmApiKeyMask ? '当前：' + ag.llmApiKeyMask + '（留空不修改）' : '填写密钥'" />
            </el-form-item>
            <el-form-item label="模型名">
              <el-input v-model="ag.llmModel" placeholder="如 qwen2.5-72b-instruct" style="width:220px" />
            </el-form-item>
            <el-form-item label="调用超时">
              <el-input-number v-model="ag.llmTimeoutMs" :min="500" :max="60000" :step="500" />
              <span class="hint">毫秒</span>
            </el-form-item>
            <el-form-item label="失败重试">
              <el-input-number v-model="ag.llmMaxRetries" :min="0" :max="5" />
            </el-form-item>
            <el-form-item label="最大输出 token">
              <el-input-number v-model="ag.llmMaxTokens" :min="64" :max="4096" :step="64" />
            </el-form-item>
          </div>
          <div class="cfg-actions">
            <el-button type="primary" :loading="savingAg" @click="saveAg">保存并发布</el-button>
          </div>
        </el-form>

        <div class="sub-title">研判轨迹
          <span class="hint" style="margin-left:8px">最近 {{ traces.length }} 条 / 共 {{ traceTotal }} 条</span>
          <el-button size="small" style="margin-left:10px" @click="loadTraces">刷新</el-button>
          <el-button size="small" type="danger" style="margin-left:6px" @click="clearTraces">清空轨迹</el-button>
        </div>
        <DataTable :data="traces" :columns="traceCols" :header-search="false" height="calc(100vh - 620px)"
                   :page-size="20" :page-sizes="[20, 50, 100]">
          <template #cell-ts="{ row }">{{ fmt(row.ts) }}</template>
          <template #cell-uri="{ row }"><code>{{ (row.method || '') + ' ' + (row.uri || '') }}</code></template>
          <template #cell-attack="{ row }">
            <el-tag :type="row.attack ? 'danger' : 'success'" size="small">{{ row.attack ? '判危' : '放行' }}</el-tag>
          </template>
          <template #cell-score="{ row }"><span class="num">{{ Number(row.score || 0).toFixed(2) }}</span></template>
          <template #cell-llmUsed="{ row }">
            <el-tag size="small" :type="row.llmUsed ? 'warning' : 'info'" effect="plain">
              {{ row.llmUsed ? '大模型' : '取证' }}
            </el-tag>
          </template>
          <template #cell-category="{ row }">{{ row.category || '-' }}</template>
          <template #cell-evidence="{ row }">{{ (row.evidence || []).join('; ') || '-' }}</template>
        </DataTable>
      </el-tab-pane>
    </el-tabs>

    <!-- 登记资产 -->
    <el-dialog v-model="invDlg" :title="invForm.id ? '编辑资产登记' : '登记 API 资产'" width="500px" append-to-body>
      <el-form label-width="90px">
        <el-form-item label="所属应用">
          <el-select v-model="invForm.appId" placeholder="全部应用" style="width:100%">
            <el-option label="全部应用" value="" />
            <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
          </el-select>
        </el-form-item>
        <el-form-item label="请求方法">
          <el-select v-model="invForm.method" style="width:100%">
            <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
          </el-select>
        </el-form-item>
        <el-form-item label="路径模板" required>
          <el-input v-model="invForm.path" maxlength="255" placeholder="如 /api/user/{id}" />
        </el-form-item>
        <el-form-item label="资产名称"><el-input v-model="invForm.name" maxlength="128" /></el-form-item>
        <el-form-item label="责任人"><el-input v-model="invForm.owner" maxlength="64" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="invForm.remark" maxlength="255" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="invForm.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="invDlg = false">取消</el-button>
        <el-button type="primary" :loading="savingInv" @click="saveInv">保存并发布</el-button>
      </template>
    </el-dialog>

    <!-- 批量导入 -->
    <el-dialog v-model="impDlg" title="批量导入 API 资产登记" width="560px" append-to-body>
      <el-alert type="warning" :closable="false" show-icon style="margin-bottom:10px"
        title="仅支持 CSV（Excel 可另存为 CSV UTF-8）。列顺序：序号, 请求格式, 接口, 所属应用, 资产名称, 责任人, 备注。" />
      <div class="imp-actions">
        <el-button size="small" @click="downloadTemplate">下载表格模板</el-button>
        <el-upload ref="upRef" :auto-upload="false" :limit="1" accept=".csv" :on-change="onPick" :on-remove="onPick"
                   :file-list="fileList" style="display:inline-block;margin-left:8px">
          <el-button size="small" type="primary">选择 CSV 文件</el-button>
        </el-upload>
      </div>
      <div v-if="impResult" class="imp-result">
        <div class="ok">导入成功：<b>{{ impResult.added }}</b> 条；跳过：<b>{{ impResult.skipped }}</b> 条</div>
        <div v-if="impResult.failed && impResult.failed.length" class="bad">
          失败 {{ impResult.failed.length }} 条：
          <ul><li v-for="(x, i) in impResult.failed" :key="i">第 {{ x.line }} 行 {{ x.path }} — {{ x.reason }}</li></ul>
        </div>
      </div>
      <template #footer>
        <el-button @click="impDlg = false">关闭</el-button>
        <el-button type="primary" :loading="importing" :disabled="!impFile" @click="doImport">开始导入</el-button>
      </template>
    </el-dialog>

    <!-- 限流策略 -->
    <el-dialog v-model="ruleDlg" :title="ruleForm.id ? '编辑限流策略' : '新增限流策略'" width="520px" append-to-body>
      <el-form label-width="110px">
        <el-form-item label="策略名称" required><el-input v-model="ruleForm.name" maxlength="64" /></el-form-item>
        <el-form-item label="所属应用">
          <el-select v-model="ruleForm.appId" placeholder="全部应用" style="width:100%">
            <el-option label="全部应用" value="" />
            <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
          </el-select>
        </el-form-item>
        <el-form-item label="请求方法">
          <el-select v-model="ruleForm.method" style="width:100%">
            <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
          </el-select>
        </el-form-item>
        <el-form-item label="路径/前缀" required>
          <el-input v-model="ruleForm.path" maxlength="255" placeholder="如 /api/order/*" />
        </el-form-item>
        <el-form-item label="QPS" required>
          <el-input-number v-model="ruleForm.qps" :min="1" :max="1000000" />
        </el-form-item>
        <el-form-item label="突发桶容量">
          <el-input-number v-model="ruleForm.burst" :min="1" :max="1000000" />
        </el-form-item>
        <el-form-item label="限流维度">
          <el-radio-group v-model="ruleForm.scope">
            <el-radio value="ip">按 IP</el-radio>
            <el-radio value="token">按令牌</el-radio>
            <el-radio value="global">全局</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="超限动作">
          <el-radio-group v-model="ruleForm.action">
            <el-radio value="monitor">仅记录</el-radio>
            <el-radio value="429">返回 429</el-radio>
            <el-radio value="ban">临时封禁</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="ruleForm.action === 'ban'" label="封禁时长">
          <el-input-number v-model="ruleForm.banSec" :min="1" :max="86400" />
          <span class="hint">秒（60 秒内多次超限升级为规则级封禁）</span>
        </el-form-item>
        <el-form-item label="要求合法令牌"><el-switch v-model="ruleForm.tokenRequired" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="ruleForm.remark" maxlength="255" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="ruleForm.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="ruleDlg = false">取消</el-button>
        <el-button type="primary" :loading="savingRule" @click="saveRule">保存并发布</el-button>
      </template>
    </el-dialog>

    <!-- 令牌 -->
    <el-dialog v-model="tokenDlg" :title="tokenForm.id ? '编辑令牌' : '新增令牌'" width="500px" append-to-body>
      <el-form label-width="100px">
        <el-form-item label="令牌名称" required><el-input v-model="tokenForm.name" maxlength="64" /></el-form-item>
        <el-form-item label="令牌值" required>
          <el-input v-model="tokenForm.token" maxlength="512" placeholder="不透明令牌原文" />
        </el-form-item>
        <el-form-item label="所属应用">
          <el-select v-model="tokenForm.appId" placeholder="全部应用" style="width:100%">
            <el-option label="全部应用" value="" />
            <el-option v-for="a in apps" :key="a.id" :label="a.name" :value="String(a.id)" />
          </el-select>
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="tokenForm.expireTime" type="datetime" placeholder="留空=永久"
                          value-format="YYYY-MM-DDTHH:mm:ss" style="width:100%" />
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="tokenForm.remark" maxlength="255" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="tokenForm.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="tokenDlg = false">取消</el-button>
        <el-button type="primary" :loading="savingToken" @click="saveToken">保存并发布</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import DataTable from '../components/DataTable.vue'

const METHODS = ['ANY', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
const tab = ref('dir')
const loading = ref(false)
const apps = ref([])

/* ---------------- 资产目录 ---------------- */
const assets = ref([])
const sum = reactive({ total: 0, shadow: 0, zombie: 0, registered: 0, new24h: 0, inventory: 0 })
const f = reactive({ kind: '', appId: '', method: '', keyword: '' })

const assetCols = [
  { label: '状态', width: 100, slot: 'kind' },
  { label: '所属应用', minWidth: 120, slot: 'appName' },
  { prop: 'method', label: '方法', width: 82 },
  { label: '路径模板', minWidth: 220, slot: 'template' },
  { label: '访问量', width: 100, slot: 'count', align: 'right' },
  { label: '5xx', width: 80, slot: 'errCount', align: 'right' },
  { label: '鉴权', width: 66, slot: 'auth' },
  { label: '敏感参数', width: 86, slot: 'sensitive' },
  { label: '状态码分布', minWidth: 150, slot: 'status' },
  { label: '最后访问', width: 160, slot: 'lastSeen' },
  { label: '操作', width: 80, fixed: 'right', slot: 'op' }
]

const riskCount = computed(() => assets.value.filter((a) => a.kind === 'shadow' || a.kind === 'zombie').length)

function kindText(k) { return { shadow: '影子', zombie: '僵尸', registered: '已登记' }[k] || k }
function kindTag(k) { return { shadow: 'danger', zombie: 'warning', registered: 'success' }[k] || 'info' }
function fmtStatus(s) {
  if (!s || typeof s !== 'object') return '-'
  return Object.keys(s).map((k) => k + ':' + s[k]).join(' ')
}
function fmtNum(n) {
  if (n == null) return '0'
  const v = Number(n)
  if (v >= 1e8) return (v / 1e8).toFixed(2) + '亿'
  if (v >= 1e4) return (v / 1e4).toFixed(1) + '万'
  return v.toLocaleString()
}
function fmt(t) {
  if (!t) return '-'
  const d = new Date(Number(t) < 1e11 ? Number(t) * 1000 : Number(t))
  if (isNaN(d.getTime())) return String(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

async function loadAssets() {
  loading.value = true
  try {
    const r = (await api.apiAssetList({ ...f, page: 1, size: 1000 })) || {}
    assets.value = r.items || []
    Object.assign(sum, r.summary || {})
  } catch (e) { /* 拦截器已提示 */ } finally { loading.value = false }
}
function resetFilter() { Object.assign(f, { kind: '', appId: '', method: '', keyword: '' }); loadAssets() }

/* ---------------- 登记清单 ---------------- */
const invRows = ref([])
const invKw = ref('')
const invFiltered = computed(() => {
  const kw = invKw.value.trim().toLowerCase()
  if (!kw) return invRows.value
  return invRows.value.filter((r) =>
    String(r.path || '').toLowerCase().includes(kw) ||
    String(r.name || '').toLowerCase().includes(kw) ||
    String(r.owner || '').toLowerCase().includes(kw))
})
const invCols = [
  { label: '所属应用', minWidth: 120, slot: 'appName' },
  { prop: 'method', label: '方法', width: 82 },
  { label: '路径模板', minWidth: 220, slot: 'path' },
  { prop: 'name', label: '资产名称', minWidth: 130 },
  { prop: 'owner', label: '责任人', width: 100 },
  { label: '状态', width: 80, slot: 'enabled' },
  { prop: 'remark', label: '备注', minWidth: 150 },
  { label: '更新时间', width: 165, slot: 'updateTime' },
  { label: '操作', width: 180, fixed: 'right', slot: 'op' }
]

const invDlg = ref(false)
const savingInv = ref(false)
const invForm = reactive({ id: null, appId: '', method: 'GET', path: '', name: '', owner: '', remark: '', enabled: true })

async function loadInventory() {
  try { invRows.value = (await api.apiAssetInventory()) || [] } catch (e) { invRows.value = [] }
}
function resetInvForm() { Object.assign(invForm, { id: null, appId: '', method: 'GET', path: '', name: '', owner: '', remark: '', enabled: true }) }
function openInvCreate() { resetInvForm(); invDlg.value = true }
function openInvEdit(row) {
  Object.assign(invForm, { enabled: true, ...row, appId: row.appId == null ? '' : String(row.appId) })
  invDlg.value = true
}
async function saveInv() {
  if (!invForm.path.trim().startsWith('/')) { ElMessage.warning('路径必须以 / 开头'); return }
  savingInv.value = true
  try {
    if (invForm.id) await api.apiAssetUpdate({ ...invForm })
    else await api.apiAssetAdd({ ...invForm })
    ElMessage.success('已保存并发布'); invDlg.value = false; loadInventory(); loadAssets()
  } catch (e) { /* 拦截器已提示 */ } finally { savingInv.value = false }
}
async function toggleInv(row) {
  await api.apiAssetToggle(row.id, !(row.enabled === true))
  ElMessage.success('已更新并发布'); loadInventory(); loadAssets()
}
async function delInv(row) {
  await ElMessageBox.confirm(`确定删除登记「${row.method} ${row.path}」吗？删除后该接口可能重新被判为影子 API。`, '提示', { type: 'warning' })
  await api.apiAssetDelete(row.id)
  ElMessage.success('已删除并发布'); loadInventory(); loadAssets()
}
async function promoteOne(row) {
  try {
    const r = await api.apiAssetPromote([{ appId: row.appId || '', method: row.method, path: row.template, name: (row.template || '').slice(0, 120), enabled: true }])
    ElMessage.success(r && r.added ? '已登记并发布' : '该资产已在清单中')
    loadInventory(); loadAssets()
  } catch (e) { /* 拦截器已提示 */ }
}
async function promoteFiltered() {
  if (!riskCount.value) return
  await ElMessageBox.confirm(
    `将当前列表中的 ${riskCount.value} 个影子/僵尸 API 登记为已管控资产（已存在自动跳过）？`, '确认登记',
    { type: 'warning' })
  const items = assets.value
    .filter((a) => a.kind === 'shadow' || a.kind === 'zombie')
    .map((a) => ({ appId: a.appId || '', method: a.method, path: a.template, name: (a.template || '').slice(0, 120), enabled: true }))
  const r = await api.apiAssetPromote(items)
  ElMessage.success(`登记完成：新增 ${r.added} 条，跳过 ${r.skipped} 条`)
  loadInventory(); loadAssets()
}

/* ---------------- CSV 导入 ---------------- */
const impDlg = ref(false), impFile = ref(null), fileList = ref([]), importing = ref(false), impResult = ref(null), upRef = ref(null)
function openImport() { impResult.value = null; impFile.value = null; fileList.value = []; impDlg.value = true }
function onPick(file) { impFile.value = file && file.raw ? file.raw : null; fileList.value = file ? [file] : [] }
async function downloadTemplate() {
  try {
    const blob = await api.apiAssetTemplate()
    const url = URL.createObjectURL(new Blob([blob], { type: 'text/csv;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url; a.download = 'API资产登记导入模板.csv'
    document.body.appendChild(a); a.click(); a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 3000)
  } catch (e) { ElMessage.error('模板下载失败') }
}
async function doImport() {
  if (!impFile.value) { ElMessage.warning('请先选择 CSV 文件'); return }
  importing.value = true
  try {
    const fd = new FormData(); fd.append('file', impFile.value)
    impResult.value = (await api.apiAssetImport(fd)) || { added: 0, skipped: 0, failed: [] }
    ElMessage.success('导入完成，新增 ' + (impResult.value.added || 0) + ' 条')
    loadInventory(); loadAssets()
  } catch (e) { /* 拦截器已提示 */ } finally { importing.value = false }
}

/* ---------------- API 策略 ---------------- */
const cfg = reactive({
  enabled: true, stage: 'monitor', tokenEnabled: true, tokenEnforce: false, tokenMode: 'any', tokenAlg: 'HS256',
  tokenSecret: '', tokenMaxAge: 86400, tokenRequireIat: false, tokenReuseWindow: 60, tokenReuseMaxIps: 8,
  tokenEnforceReuse: false, dlpEnabled: false, dlpAction: 'mask', dlpMaxBytes: 1048576
})
const savingCfg = ref(false)

async function loadCfg() {
  try {
    const r = (await api.apiGuardConfig()) || {}
    Object.assign(cfg, r)
  } catch (e) { /* 拦截器已提示 */ }
}
async function saveCfg() {
  savingCfg.value = true
  try {
    const r = await api.apiGuardSaveConfig({ ...cfg })
    Object.assign(cfg, r || {})
    ElMessage.success('配置已发布，引擎约 5 秒内生效')
  } catch (e) { /* 拦截器已提示 */ } finally { savingCfg.value = false }
}

const rules = ref([])
const ruleDlg = ref(false), savingRule = ref(false)
const ruleForm = reactive({ id: null, name: '', appId: '', method: 'GET', path: '', qps: 10, burst: 20, scope: 'ip', action: '429', banSec: 60, tokenRequired: false, remark: '', enabled: true })
const ruleCols = [
  { label: '所属应用', minWidth: 110, slot: 'appName' },
  { prop: 'name', label: '策略名称', minWidth: 130 },
  { prop: 'method', label: '方法', width: 80 },
  { label: '路径', minWidth: 180, slot: 'path' },
  { prop: 'qps', label: 'QPS', width: 80, align: 'right' },
  { prop: 'burst', label: '突发', width: 76, align: 'right' },
  { label: '维度', width: 80, slot: 'scope' },
  { label: '动作', width: 96, slot: 'action' },
  { label: '令牌', width: 76, slot: 'tokenRequired' },
  { prop: 'remark', label: '备注', minWidth: 130 },
  { label: '状态', width: 78, slot: 'enabled' },
  { label: '操作', width: 180, fixed: 'right', slot: 'op' }
]
function scopeText(s) { return { ip: '按 IP', token: '按令牌', global: '全局' }[s] || s }
function actionText(a) { return { monitor: '仅记录', 429: '返回429', ban: '临时封禁' }[a] || a }

async function loadRules() { try { rules.value = (await api.apiGuardList()) || [] } catch (e) { rules.value = [] } }
function resetRule() { Object.assign(ruleForm, { id: null, name: '', appId: '', method: 'GET', path: '', qps: 10, burst: 20, scope: 'ip', action: '429', banSec: 60, tokenRequired: false, remark: '', enabled: true }) }
function openRuleCreate() { resetRule(); ruleDlg.value = true }
function openRuleEdit(row) { Object.assign(ruleForm, { enabled: true, ...row, appId: row.appId == null ? '' : String(row.appId) }); ruleDlg.value = true }
async function saveRule() {
  if (!ruleForm.name.trim()) { ElMessage.warning('请填写策略名称'); return }
  if (!ruleForm.path.trim().startsWith('/')) { ElMessage.warning('路径必须以 / 开头'); return }
  savingRule.value = true
  try {
    if (ruleForm.id) await api.apiGuardUpdate({ ...ruleForm })
    else await api.apiGuardCreate({ ...ruleForm })
    ElMessage.success('已保存并发布'); ruleDlg.value = false; loadRules()
  } catch (e) { /* 拦截器已提示 */ } finally { savingRule.value = false }
}
async function toggleRule(row) { await api.apiGuardToggle(row.id, !(row.enabled === true)); ElMessage.success('已更新并发布'); loadRules() }
async function delRule(row) {
  await ElMessageBox.confirm(`确定删除策略「${row.name}」吗？`, '提示', { type: 'warning' })
  await api.apiGuardDelete(row.id); ElMessage.success('已删除并发布'); loadRules()
}

/* ---------------- 令牌白名单 ---------------- */
const tokens = ref([])
const tokenDlg = ref(false), savingToken = ref(false)
const tokenForm = reactive({ id: null, name: '', token: '', appId: '', expireTime: '', remark: '', enabled: true })
const tokenCols = [
  { prop: 'name', label: '令牌名称', minWidth: 130 },
  { label: '令牌值', minWidth: 180, slot: 'tokenMask' },
  { label: '所属应用', minWidth: 110, slot: 'appName' },
  { label: '过期时间', width: 165, slot: 'expireTime' },
  { prop: 'remark', label: '备注', minWidth: 140 },
  { label: '状态', width: 78, slot: 'enabled' },
  { label: '操作', width: 180, fixed: 'right', slot: 'op' }
]
async function loadTokens() { try { tokens.value = (await api.apiGuardTokens()) || [] } catch (e) { tokens.value = [] } }
function resetToken() { Object.assign(tokenForm, { id: null, name: '', token: '', appId: '', expireTime: '', remark: '', enabled: true }) }
function openTokenCreate() { resetToken(); tokenDlg.value = true }
function openTokenEdit(row) {
  Object.assign(tokenForm, { enabled: true, ...row, appId: row.appId == null ? '' : String(row.appId), token: row.tokenMask || '' })
  tokenDlg.value = true
}
async function saveToken() {
  if (!tokenForm.name.trim()) { ElMessage.warning('请填写令牌名称'); return }
  if (!tokenForm.token || !tokenForm.token.trim()) { ElMessage.warning('请填写令牌值'); return }
  savingToken.value = true
  try {
    const body = { ...tokenForm }
    if (!body.expireTime) body.expireTime = null
    if (body.id) await api.apiGuardUpdateToken(body)
    else await api.apiGuardAddToken(body)
    ElMessage.success('已保存并发布'); tokenDlg.value = false; loadTokens()
  } catch (e) { /* 拦截器已提示 */ } finally { savingToken.value = false }
}
async function toggleToken(row) { await api.apiGuardToggleToken(row.id, !(row.enabled === true)); ElMessage.success('已更新并发布'); loadTokens() }
async function delToken(row) {
  await ElMessageBox.confirm(`确定删除令牌「${row.name}」吗？删除后使用该令牌的请求将被拒绝。`, '提示', { type: 'warning' })
  await api.apiGuardDeleteToken(row.id); ElMessage.success('已删除并发布'); loadTokens()
}

/* ---------------- Agentic AI ---------------- */
const ag = reactive({
  enabled: false, block: false, threshold: 0.6, maxSteps: 4, budgetPerMin: 20, cacheTtlSec: 300, traceMax: 2000,
  llmEnabled: false, llmEndpoint: '', llmApiKey: '', llmApiKeyMask: '', llmModel: '', llmTimeoutMs: 8000, llmMaxRetries: 1, llmMaxTokens: 512
})
const savingAg = ref(false)
const traces = ref([])
const traceTotal = ref(0)
const traceCols = [
  { label: '时间', width: 165, slot: 'ts' },
  { prop: 'ip', label: '来源 IP', width: 130 },
  { label: '请求', minWidth: 200, slot: 'uri' },
  { label: '判定', width: 78, slot: 'attack' },
  { label: '评分', width: 76, slot: 'score', align: 'right' },
  { label: '来源', width: 90, slot: 'llmUsed' },
  { label: '威胁类型', width: 130, slot: 'category' },
  { label: '取证证据', minWidth: 260, slot: 'evidence' },
  { prop: 'reason', label: '研判结论', minWidth: 200 }
]
async function loadAg() {
  try {
    const r = (await api.agenticConfig()) || {}
    Object.assign(ag, r, { llmApiKey: '' })
  } catch (e) { /* 拦截器已提示 */ }
}
async function saveAg() {
  savingAg.value = true
  try {
    await api.agenticSaveConfig({ ...ag })
    ElMessage.success('配置已发布，引擎约 5 秒内生效'); loadAg()
  } catch (e) { /* 拦截器已提示 */ } finally { savingAg.value = false }
}
async function loadTraces() {
  try {
    const r = (await api.agenticTraces(200)) || {}
    traces.value = r.items || []
    traceTotal.value = r.total || 0
  } catch (e) { traces.value = [] }
}
async function clearTraces() {
  await ElMessageBox.confirm('确定清空引擎中的研判轨迹吗？', '提示', { type: 'warning' })
  await api.agenticClearTraces(); ElMessage.success('已清空'); loadTraces()
}

/* ---------------- 生命周期 ---------------- */
let timer = null
onMounted(async () => {
  try { apps.value = (await api.wafApps()) || [] } catch (e) { apps.value = [] }
  await Promise.all([loadAssets(), loadInventory(), loadCfg(), loadRules(), loadTokens(), loadAg(), loadTraces()])
  // 资产目录/轨迹为引擎异步产出，30s 静默刷新一次（不打断用户操作）
  timer = setInterval(() => {
    if (tab.value === 'dir') loadAssets()
    else if (tab.value === 'agentic') loadTraces()
  }, 30000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.p { padding: 14px; }
.api-tabs :deep(.el-tabs__content) { padding: 12px; }
.stat-row { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.stat {
  flex: 1; min-width: 132px; padding: 10px 12px; border-radius: 6px;
  border: 1px solid rgba(0, 229, 255, .18); background: rgba(0, 229, 255, .04);
}
.stat .k { display: block; font-size: 12px; color: var(--muted, #889); }
.stat .v { display: block; font-size: 22px; line-height: 1.4; color: #7fe7ff; font-variant-numeric: tabular-nums; }
.stat.warn .v { color: #ffb454; }
.stat.bad .v { color: #ff6b81; }
.stat.ok .v { color: #5fe6a8; }
.filter-bar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  margin-bottom: 10px; padding: 8px 10px;
  border: 1px solid rgba(0, 229, 255, .18); border-radius: 6px; background: rgba(0, 229, 255, .04);
}
.f-inp { width: 150px; }
.f-inp-lg { width: 230px; }
.f-sel { width: 150px; }
.f-sel-sm { width: 96px; }
.f-count { font-size: 12px; color: var(--muted, #889); }
.f-count b { color: #7fe7ff; }
.num { font-variant-numeric: tabular-nums; font-weight: 600; color: #7fe7ff; }
.num.bad { color: #ff6b81; }
.ok { color: #5fe6a8; }
.bad { color: #ff6b81; }
.muted { color: var(--muted, #889); }
.hint { margin-left: 8px; font-size: 12px; color: var(--muted, #889); }
.sub-title { margin: 16px 0 10px; font-weight: 600; color: #7fe7ff; }
.cfg-form { max-height: 420px; overflow: auto; padding-right: 6px; }
.cfg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 0 12px; }
.cfg-actions { margin-top: 6px; }
.imp-actions { display: flex; align-items: center; }
.imp-result { margin-top: 10px; font-size: 13px; }
.imp-result .ok { color: #5fe6a8; }
.imp-result .bad { color: #ff6b81; margin-top: 4px; }
.imp-result ul { margin: 4px 0 0 18px; }
</style>
