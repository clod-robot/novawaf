#!/bin/bash
# 用 root 凭据建库 + 专用账号 + 导入 DDL
ROOTPASS='MAO5201314sm'
DB='novawaf_admin'
APPUSER='waf_admin'
# 生成强密码(去掉易混字符)
APPPASS=$(openssl rand -base64 15 | tr -d '/+=' | head -c 16)
DDL=/home/mao/novawaf/admin-server/sql/novawaf_admin.sql

echo "Testing root login..."
mysql -uroot -p"${ROOTPASS}" -e "SELECT VERSION();" >/dev/null 2>&1 || { echo "ROOT_LOGIN_FAIL"; exit 1; }

mysql -uroot -p"${ROOTPASS}" <<SQL
CREATE DATABASE IF NOT EXISTS ${DB} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${APPUSER}'@'%' IDENTIFIED BY '${APPPASS}';
CREATE USER IF NOT EXISTS '${APPUSER}'@'localhost' IDENTIFIED BY '${APPPASS}';
ALTER USER '${APPUSER}'@'%' IDENTIFIED WITH mysql_native_password BY '${APPPASS}';
ALTER USER '${APPUSER}'@'localhost' IDENTIFIED WITH mysql_native_password BY '${APPPASS}';
GRANT ALL PRIVILEGES ON ${DB}.* TO '${APPUSER}'@'%';
GRANT ALL PRIVILEGES ON ${DB}.* TO '${APPUSER}'@'localhost';
FLUSH PRIVILEGES;
SQL
echo "DB_AND_USER_CREATED"

mysql -u"${APPUSER}" -p"${APPPASS}" "${DB}" < "${DDL}" && echo "DDL_IMPORTED" || { echo "DDL_FAILED"; exit 2; }

# 校验账号可连 + 表存在
CNT=$(mysql -u"${APPUSER}" -p"${APPPASS}" "${DB}" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB}';")
echo "TABLE_COUNT=$CNT"
echo "CREDENTIALS db=${DB} user=${APPUSER} pass=${APPPASS}"
