package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ========== 排除列表：在此添加不需要生成策略的规则名 ==========
var excludeRules = map[string]bool{
	"19102-XKP-S2":   true,
	"19102-XKP-S1":   true,
	"191-RDP-STXF":   true,
	"Zs-FTP-ZWLS":    true,
	"ZsAn-YCLS":      true,
	"ZsAn-CYUE-RDP":  true,
	"ZsAn-CYUE-MS":   true,
	"192-LDAP7-1":    true,
	"198-ZSW-ZDMQA":  true,
	"198-ZYDM-ZSWBF": true,
	"XKP-DB":         true,
	"AT-DB":          true,
	"YbVD-WeCMems":   true,
	"Ay-MGSV":        true,
	"XKP-DBoMC":      true,
	"YnXiaoLe-WeXRK": true,
	"YN-DB":          true,
	"191-SPN-FRBI":   true,
	"191-SPN-XKP":    true,
}

type PolicyData struct {
	RuleName   string
	SrcZone    string
	SrcAddress string
	DstZone    string
	DstAddress string
	Service    string
	Action     string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go <你的excel文件名.xlsx>")
		os.Exit(1)
	}

	excelFile := os.Args[1]
	outputStr, total, skipped := ConvertExcelToFirewallRules(excelFile)

	fmt.Println(outputStr)

	err := os.WriteFile("firewall_rules.txt", []byte(outputStr), 0644)
	if err != nil {
		fmt.Printf("\n保存文件失败: %v\n", err)
	} else {
		fmt.Printf("\n成功！已生成配置文件到 'firewall_rules.txt'\n")
		fmt.Printf("总策略数: %d | 已排除: %d | 实际生成: %d\n", total, skipped, total-skipped)
	}
}

func ConvertExcelToFirewallRules(filename string) (string, int, int) {
	file, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println("无法打开文件:", err.Error())
		return "", 0, 0
	}
	defer func() {
		_ = file.Close()
	}()

	sheetName := file.GetSheetName(0)
	if sheetName == "" {
		fmt.Println("未找到有效的工作表")
		return "", 0, 0
	}

	rows, err := file.GetRows(sheetName)
	if err != nil {
		fmt.Println("读取数据失败:", err.Error())
		return "", 0, 0
	}

	var sb strings.Builder
	sb.WriteString("security-policy\n")

	total := 0
	skipped := 0

	for i, row := range rows {
		if i < 1 {
			continue
		}

		if len(row) < 2 || strings.TrimSpace(row[1]) == "" {
			continue
		}

		policy := PolicyData{
			RuleName:   getCell(row, 1),
			SrcZone:    getCell(row, 2),
			SrcAddress: getCell(row, 3),
			DstZone:    getCell(row, 4),
			DstAddress: getCell(row, 5),
			Service:    getCell(row, 6),
			Action:     getCell(row, 8),
		}

		if policy.RuleName == "" {
			continue
		}

		total++

		// ========== 核心：检查是否在排除列表中 ==========
		if excludeRules[policy.RuleName] {
			skipped++
			fmt.Printf("[已排除] rule name %s\n", policy.RuleName)
			continue
		}

		sb.WriteString(generateRule(policy))
		sb.WriteString("\n")
	}

	return sb.String(), total, skipped
}

func generateRule(p PolicyData) string {
	var lines []string

	lines = append(lines, fmt.Sprintf(" rule name %s", p.RuleName))

	// source-zone
	for _, z := range splitLines(p.SrcZone) {
		lines = append(lines, fmt.Sprintf("  source-zone %s", z))
	}

	// destination-zone
	for _, z := range splitLines(p.DstZone) {
		lines = append(lines, fmt.Sprintf("  destination-zone %s", z))
	}

	// source-address
	srcAddrs := splitLines(p.SrcAddress)
	if len(srcAddrs) > 0 {
		allAny := true
		for _, addr := range srcAddrs {
			if !isAny(addr) {
				allAny = false
				break
			}
		}
		if allAny {
			lines = append(lines, "  source-address any")
		} else {
			for _, addr := range srcAddrs {
				if isAny(addr) {
					continue
				}
				lines = append(lines, fmt.Sprintf("  source-address address-set %s", addr))
			}
		}
	}

	// destination-address
	dstAddrs := splitLines(p.DstAddress)
	if len(dstAddrs) > 0 {
		allAny := true
		for _, addr := range dstAddrs {
			if !isAny(addr) {
				allAny = false
				break
			}
		}
		if allAny {
			lines = append(lines, "  destination-address any")
		} else {
			for _, addr := range dstAddrs {
				if isAny(addr) {
					continue
				}
				lines = append(lines, fmt.Sprintf("  destination-address address-set %s", addr))
			}
		}
	}

	// service
	svcs := splitLines(p.Service)
	for _, svc := range svcs {
		if isAny(svc) {
			continue
		}
		lines = append(lines, formatService(svc))
	}

	// action
	if p.Action != "" {
		lines = append(lines, fmt.Sprintf("  action %s", strings.ToLower(p.Action)))
	}

	return strings.Join(lines, "\n") + "\n"
}

func formatService(svc string) string {
	lower := strings.ToLower(strings.TrimSpace(svc))

	// 纯协议名
	if lower == "tcp" {
		return "  service tcp"
	}
	if lower == "udp" {
		return "  service udp"
	}
	if lower == "icmp" || lower == "ping" {
		return "  service icmp"
	}

	// 带冒号: udp:123 / tcp：8080 → 去掉冒号拼成 service-set 名
	if strings.ContainsAny(svc, ":：") {
		cleaned := strings.ReplaceAll(svc, "：", "")
		cleaned = strings.ReplaceAll(cleaned, ":", "")
		cleaned = strings.TrimSpace(cleaned)
		return fmt.Sprintf("  service service-set %s", cleaned)
	}

	// 其他普通服务名
	return fmt.Sprintf("  service service-set %s", strings.TrimSpace(svc))
}

// ========== 工具函数 ==========

func isAny(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	return lower == "全部" || lower == "any" || lower == "all"
}

func splitLines(text string) []string {
	parts := strings.Split(text, "\n")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		cleaned := strings.TrimSpace(p)
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	return result
}

func getCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}
