package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/xuri/excelize/v2"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go <你的excel文件名.xlsx>")
		os.Exit(1)
	}

	excelFile := os.Args[1]
	output, count := ConvertToStaticRoutes(excelFile)

	fmt.Println(output)

	err := os.WriteFile("static_routes.txt", []byte(output), 0644)
	if err != nil {
		fmt.Printf("保存文件失败: %v\n", err)
	} else {
		fmt.Printf("\n成功！已生成 'static_routes.txt'，共 %d 条路由\n", count)
	}
}

func ConvertToStaticRoutes(filename string) (string, int) {
	file, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return "", 0
	}
	defer func() { _ = file.Close() }()

	sheetName := file.GetSheetName(0)
	rows, err := file.GetRows(sheetName)
	if err != nil {
		fmt.Println("读取失败:", err)
		return "", 0
	}

	var sb strings.Builder
	count := 0

	for i, row := range rows {
		// 跳过表头
		if i < 1 {
			continue
		}

		if len(row) < 3 {
			continue
		}

		// 读取并清洗（去掉所有空格，Excel中IP可能带空格如 "10. 141. 251. 0"）
		dstIP := cleanIP(row[0])
		mask := cleanIP(row[1])
		nextHop := cleanIP(row[2])

		if dstIP == "" || mask == "" || nextHop == "" {
			continue
		}

		// 掩码转CIDR数字
		cidr, err := maskToCIDR(mask)
		if err != nil {
			fmt.Printf("[警告] 第%d行掩码转换失败: %s -> %v\n", i+1, mask, err)
			// 转换失败就保留原始掩码格式
			sb.WriteString(fmt.Sprintf("ip route-static %s %s %s\n", dstIP, mask, nextHop))
		} else {
			sb.WriteString(fmt.Sprintf("ip route-static %s %d %s\n", dstIP, cidr, nextHop))
		}
		count++
	}

	return sb.String(), count
}

// cleanIP 去除IP地址中的所有空格
// 例如 "10. 141. 251. 0" → "10.141.251.0"
func cleanIP(raw string) string {
	return strings.ReplaceAll(strings.TrimSpace(raw), " ", "")
}

// maskToCIDR 将子网掩码转换为CIDR数字
// 例如 "255.255.255.0" → 24
//
//	"255.255.255.224" → 27
//	"255.255.255.128" → 25
//	"255.255.254.0" → 23
//	"0.0.0.0" → 0
func maskToCIDR(mask string) (int, error) {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0, fmt.Errorf("无效掩码: %s", mask)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("非IPv4掩码: %s", mask)
	}

	ipMask := net.IPv4Mask(ip4[0], ip4[1], ip4[2], ip4[3])
	ones, _ := ipMask.Size()
	return ones, nil
}
