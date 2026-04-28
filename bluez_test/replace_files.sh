#!/bin/bash

# 默认目标目录为当前目录下的 bluez-5.86，也可以通过第一个参数指定
TARGET_DIR=${1:-"./bluez-5.86"}

if [ ! -d "$TARGET_DIR" ]; then
    echo "错误: 找不到目标目录 $TARGET_DIR"
    echo "用法: ./replace_files.sh [bluez源码根目录路径]"
    exit 1
fi

echo "正在替换文件到: $TARGET_DIR"

# 执行替换
cp -v tools/mesh-cfgclient.c "$TARGET_DIR/tools/"
cp -v tools/mesh/config-model.h "$TARGET_DIR/tools/mesh/"
cp -v tools/mesh/cfgcli.c "$TARGET_DIR/tools/mesh/"

echo "--------------------------------------"
echo "文件替换完成！"
echo "现在您可以进入 $TARGET_DIR 执行以下命令进行编译："
echo "  ./bootstrap"
echo "  ./configure --enable-mesh --enable-external-ell"
echo "  make tools/mesh-cfgclient"
echo "--------------------------------------"
