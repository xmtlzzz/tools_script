package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/xuri/excelize/v2"
)

type AddressGroup struct {
	Name      string
	Addresses []string
}

func main() {
	filename := "firewall.xlsx"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}

	f, err := excelize.OpenFile(filename)
	if err != nil {
		log.Fatalf("无法打开文件 %s: %v", filename, err)
	}
	defer f.Close()

	fmt.Println("#")
	fmt.Println("# ========== 地址对象集 (Address Sets) ==========")
	fmt.Println("#")
	processAddressGroups(f)

	fmt.Println()
	fmt.Println("#")
	fmt.Println("# ========== 服务对象集 (Service Sets) ==========")
	fmt.Println("#")
	processServiceGroups(f)
}

// ===================== 地址组处理 =====================

func processAddressGroups(f *excelize.File) {
	sheetName := "地址组"
	rows, err := f.GetRows(sheetName)
	if err != nil {
		log.Printf("读取工作表 [%s] 失败: %v\n", sheetName, err)
		return
	}

	var groups []AddressGroup
	var current *AddressGroup

	for i, row := range rows {
		if i == 0 {
			continue
		}

		name, addr := "", ""
		if len(row) >= 1 {
			name = strings.TrimSpace(row[0])
		}
		if len(row) >= 2 {
			addr = strings.TrimSpace(row[1])
		}
		if addr == "" {
			continue
		}

		lines := splitCellLines(addr)

		if name != "" {
			if current != nil {
				groups = append(groups, *current)
			}
			current = &AddressGroup{
				Name:      name,
				Addresses: lines,
			}
		} else {
			if current != nil {
				current.Addresses = append(current.Addresses, lines...)
			}
		}
	}
	if current != nil {
		groups = append(groups, *current)
	}

	// ★★★ 收集所有已定义的地址组名称，用于判断引用 ★★★
	knownNames := make(map[string]bool)
	for _, g := range groups {
		knownNames[g.Name] = true
	}

	// 输出命令
	for _, g := range groups {
		// ★★★ 展开所有条目，判断是 IP 类型还是引用类型 ★★★
		allEntries := expandAllEntries(g.Addresses)

		isGroup := false
		isObject := false
		for _, entry := range allEntries {
			if looksLikeIP(entry) {
				isObject = true
			} else {
				isGroup = true
			}
		}

		if isGroup && !isObject {
			// ---- 全部是引用 → type group ----
			fmt.Printf("ip address-set %s type group\n", g.Name)
			for _, entry := range allEntries {
				fmt.Printf(" address-set %s\n", entry)
			}
		} else if isObject && !isGroup {
			// ---- 全部是 IP → type object ----
			fmt.Printf("ip address-set %s type object\n", g.Name)
			for _, entry := range allEntries {
				genSingleAddress(entry)
			}
		} else {
			// ---- 混合情况：分别输出 ----
			// 先输出 object 部分
			fmt.Printf("ip address-set %s type object\n", g.Name)
			for _, entry := range allEntries {
				if looksLikeIP(entry) {
					genSingleAddress(entry)
				}
			}
			fmt.Println("#")
			// 再输出 group 部分（需要另建一个 group）
			fmt.Printf("ip address-set %s type group\n", g.Name)
			for _, entry := range allEntries {
				if !looksLikeIP(entry) {
					fmt.Printf(" address-set %s\n", entry)
				}
			}
		}
		fmt.Println("#")
	}
}

// expandAllEntries 将所有地址条目展开为单条列表
func expandAllEntries(addresses []string) []string {
	var result []string
	for _, raw := range addresses {
		raw = normalize(raw)
		subLines := splitCellLines(raw)
		for _, line := range subLines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// ★★★ 关键：先判断整行是否像 IP ★★★
			if looksLikeIP(line) {
				// IP 类数据，可能有逗号分隔
				parts := strings.Split(line, ",")
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						result = append(result, p)
					}
				}
			} else {
				// 非 IP，可能是逗号分隔的多个引用名
				parts := strings.Split(line, ",")
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						result = append(result, p)
					}
				}
			}
		}
	}
	return result
}

// ★★★ looksLikeIP 判断一个条目是否像 IP 地址（而非地址组引用名） ★★★
func looksLikeIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	// 对于范围格式 "10.141.251.2-10.141.251.126" 或 "100.102.90.131-132"
	// 取 "-" 前面的部分检查
	checkPart := s
	if idx := strings.Index(s, "-"); idx != -1 {
		checkPart = s[:idx]
	}
	checkPart = strings.TrimSpace(checkPart)

	if len(checkPart) == 0 {
		return false
	}

	// IP 地址特征：以数字开头 且 包含 "."
	if checkPart[0] < '0' || checkPart[0] > '9' {
		return false
	}
	return strings.Contains(checkPart, ".")
}

// genSingleAddress 处理单条 IP 地址或范围
func genSingleAddress(part string) {
	part = strings.TrimSpace(part)
	if part == "" {
		return
	}

	if strings.Contains(part, "-") {
		segs := strings.SplitN(part, "-", 2)
		startIP := strings.TrimSpace(segs[0])
		endPart := strings.TrimSpace(segs[1])

		if !strings.Contains(endPart, ".") {
			// 短格式: 100.102.90.131-132
			prefix := startIP[:strings.LastIndex(startIP, ".")+1]
			endPart = prefix + endPart
		}
		fmt.Printf(" address range %s %s\n", startIP, endPart)
	} else if strings.Contains(part, "/") {
		// 子网格式: 10.141.0.0/24
		sp := strings.SplitN(part, "/", 2)
		fmt.Printf(" address %s mask %s\n", strings.TrimSpace(sp[0]), strings.TrimSpace(sp[1]))
	} else {
		fmt.Printf(" address %s mask 32\n", part)
	}
}

// ===================== 端口组处理 =====================

func processServiceGroups(f *excelize.File) {
	sheetName := "端口组"
	rows, err := f.GetRows(sheetName)
	if err != nil {
		log.Printf("读取工作表 [%s] 失败: %v\n", sheetName, err)
		return
	}

	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 2 {
			continue
		}

		name := strings.TrimSpace(row[0])
		svc := strings.TrimSpace(row[1])
		if name == "" || svc == "" {
			continue
		}

		fmt.Printf("ip service-set %s type object\n", name)
		genServiceLines(svc)
		fmt.Println("#")
	}
}

func genServiceLines(raw string) {
	raw = normalize(raw)

	subLines := splitCellLines(raw)
	for _, line := range subLines {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, "()")
		if line == "" {
			continue
		}
		parseServiceSection(line)
	}
}

func parseServiceSection(line string) {
	sections := strings.Split(line, ";")

	for _, section := range sections {
		section = strings.TrimSpace(section)
		section = strings.Trim(section, "()")
		if section == "" {
			continue
		}

		colonIdx := strings.Index(section, ":")
		if colonIdx == -1 {
			continue
		}

		protoPart := strings.ToUpper(strings.TrimSpace(section[:colonIdx]))
		portsPart := strings.TrimSpace(section[colonIdx+1:])

		var protocols []string
		if strings.Contains(protoPart, "TCP") {
			protocols = append(protocols, "tcp")
		}
		if strings.Contains(protoPart, "UDP") {
			protocols = append(protocols, "udp")
		}
		if len(protocols) == 0 {
			protocols = append(protocols, strings.ToLower(protoPart))
		}

		portEntries := strings.Split(portsPart, ",")

		for _, proto := range protocols {
			for _, pe := range portEntries {
				pe = strings.TrimSpace(pe)
				pe = strings.Trim(pe, "()")
				if pe == "" {
					continue
				}

				if strings.Contains(pe, "-") {
					rp := strings.SplitN(pe, "-", 2)
					fmt.Printf(" service protocol %s destination-port %s to %s\n",
						proto,
						strings.TrimSpace(rp[0]),
						strings.TrimSpace(rp[1]))
				} else {
					fmt.Printf(" service protocol %s destination-port %s\n",
						proto, pe)
				}
			}
		}
	}
}

// ===================== 工具函数 =====================

func splitCellLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	parts := strings.Split(s, "\n")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 && strings.TrimSpace(s) != "" {
		result = append(result, strings.TrimSpace(s))
	}
	return result
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, "，", ",")
	s = strings.ReplaceAll(s, "、", ",")
	s = strings.ReplaceAll(s, "：", ":")
	s = strings.ReplaceAll(s, "（", "(")
	s = strings.ReplaceAll(s, "）", ")")
	s = strings.ReplaceAll(s, "–", "-")
	s = strings.ReplaceAll(s, "—", "-")
	s = strings.ReplaceAll(s, "\u3000", " ")
	return s
}
