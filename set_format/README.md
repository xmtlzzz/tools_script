# 华为防火墙地址组、端口组格式化

## 环境准备
```bash
go mod tidy
```

## 使用
```bash
# 运行（默认读取 firewall.xlsx）
go run main.go

# 指定文件名
go run main.go myfile.xlsx

# 输出到文件
go run main.go firewall.xlsx > huawei_commands.txt
```
