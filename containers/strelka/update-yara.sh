#!/bin/bash
cd /app/configs/python/backend/yara/rules

# Backup
mv rules.yara rules.yara.bak 2>/dev/null

# Fetch from sources
git clone --depth 1 https://github.com/Yara-Rules/rules.git yr-temp || git -C yr-temp pull
cp -r yr-temp/* .

git clone --depth 1 https://github.com/reversinglabs/reversinglabs-yara-rules.git rl-temp || git -C rl-temp pull
cp -r rl-temp/* .

git clone --depth 1 https://github.com/Neo23x0/signature-base.git sb-temp || git -C sb-temp pull
cp -r sb-temp/yara/* .

git clone --depth 1 https://github.com/advanced-threat-research/Yara-Rules.git tr-temp || git -C tr-temp pull
cp -r tr-temp/* .

# Compile
yarac rules.yara compiled_rules.yarac

# Cleanup
rm -rf *-temp