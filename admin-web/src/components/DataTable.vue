<template>
  <div class="data-table-wrap" :style="wrapStyle">
    <el-table
      ref="tbl"
      :data="paged"
      size="small"
      stripe
      border
      v-loading="loading"
      height="100%"
      style="flex:1; width:100%"
      @sort-change="onSort"
    >
      <el-table-column
        v-for="(c, i) in columns"
        :key="i"
        :type="c.type"
        :prop="c.prop"
        :label="c.label"
        :width="c.width"
        :min-width="c.minWidth"
        :fixed="c.fixed"
        :align="c.align"
        :sortable="c.sortable ? (typeof c.sortable === 'string' ? c.sortable : 'custom') : false"
        :show-overflow-tooltip="c.tooltip !== false"
      >
        <template v-if="c.type !== 'expand'" #header>
          <div class="col-hdr">
            <span class="col-label">{{ c.label }}</span>
            <el-input
              v-if="searchable && headerSearch && !c.noSearch && c.prop && c.type !== 'index' && !c.noHeader"
              v-model="filters[c.prop]"
              size="small"
              :placeholder="'搜' + c.label"
              clearable
              class="col-search"
            />
          </div>
        </template>
        <template v-if="c.type !== 'expand' && c.type !== 'index'" #default="{ row, $index }">
          <slot :name="cellSlotName(c)" :row="row" :index="$index">
            {{ renderCell(row, c) }}
          </slot>
        </template>
        <template v-if="c.type === 'expand'" #default="{ row }">
          <slot name="expand" :row="row" />
        </template>
      </el-table-column>
      <template #empty><span class="empty">暂无数据</span></template>
    </el-table>
    <div class="dt-pager">
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="pageSizes"
        :total="filtered.length"
        layout="total, sizes, prev, pager, next, jumper"
        background
        small
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, reactive } from 'vue'

const props = defineProps({
  data: { type: Array, default: () => [] },
  columns: { type: Array, default: () => [] },
  pageSize: { type: Number, default: 50 },
  pageSizes: { type: Array, default: () => [50, 100, 150, 200] },
  searchable: { type: Boolean, default: true },
  // 表头内嵌搜索框开关：false 时由页面用独立筛选条自行过滤，避免表头重排抖动
  headerSearch: { type: Boolean, default: true },
  loading: { type: Boolean, default: false },
  height: { type: [String, Number], default: 'calc(100vh - 160px)' }
})

const page = ref(1)
const pageSize = ref(props.pageSize)
const filters = reactive({})
const sortProp = ref('')
const sortOrder = ref('')

const wrapStyle = computed(() => ({
  height: typeof props.height === 'number' ? props.height + 'px' : props.height,
  display: 'flex',
  flexDirection: 'column'
}))

// 仅在数据条数变化时回到首页；次数等原地更新不会打断当前分页（避免刷新抖动）
watch(() => (props.data || []).length, () => { page.value = 1 })

const filtered = computed(() => {
  let list = (props.data || []).slice()
  for (const k in filters) {
    const kw = (filters[k] || '').trim().toLowerCase()
    if (!kw) continue
    list = list.filter(r => String(r[k] ?? '').toLowerCase().includes(kw))
  }
  if (sortProp.value && sortOrder.value) {
    const dir = sortOrder.value === 'ascending' ? 1 : -1
    const p = sortProp.value
    list = list.slice().sort((a, b) => {
      const av = a[p], bv = b[p]
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
      return String(av ?? '').localeCompare(String(bv ?? ''), 'zh') * dir
    })
  }
  return list
})

const paged = computed(() => {
  const s = (page.value - 1) * pageSize.value
  return filtered.value.slice(s, s + pageSize.value)
})

function cellSlotName(c) { return 'cell-' + (c.slot || c.prop || 'col') }
function renderCell(row, c) {
  const v = c.prop ? row[c.prop] : ''
  if (c.type === 'index') return ''
  return v ?? ''
}

function onSort({ prop, order }) { sortProp.value = prop; sortOrder.value = order }
</script>

<style scoped>
.data-table-wrap { width: 100%; }
.col-hdr { display: flex; flex-direction: column; gap: 2px; align-items: stretch; }
.col-label { line-height: 1.2; }
.col-search { width: 100%; }
.col-search :deep(.el-input__wrapper) { padding: 0 6px; background: rgba(0,229,255,0.06); box-shadow: 0 0 0 1px rgba(0,229,255,0.2) inset; }
.col-search :deep(.el-input__inner) { height: 22px; font-size: 11px; color: #cfe9ff; }
.dt-pager { display: flex; justify-content: flex-end; margin-top: 8px; }
.dt-pager :deep(.el-pagination) { --el-pagination-bg-color: transparent; }
.empty { color: var(--muted, #889); }
</style>
