//go:build windows

package alerts

import (
	"fmt"
	"log"
	"os/exec"
)

func sendPlatformNotification(title, body, severity string) {
	// Use PowerShell to show a Windows Toast notification via WinRT
	urgency := ""
	if severity == "critical" {
		urgency = "-urgency critical"
	}
	_ = urgency

	// Build PowerShell script for toast notification
	psScript := fmt.Sprintf(
		`[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null;`+
			`$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);`+
			`$text = $template.GetElementsByTagName("text");`+
			`$text.Item(0).AppendChild($template.CreateTextNode("%s")) | Out-Null;`+
			`$text.Item(1).AppendChild($template.CreateTextNode("%s")) | Out-Null;`+
			`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Castiel").Show($template)`,
		escapeForPowerShell(title), escapeForPowerShell(body))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if err := cmd.Run(); err != nil {
		// Fallback: use msg.exe (simpler, works on Server editions)
		fallback := exec.Command("msg", "*", "/TIME:10", fmt.Sprintf("%s: %s", title, body))
		if fbErr := fallback.Run(); fbErr != nil {
			log.Printf("Desktop notification failed (toast and msg.exe): %v", err)
		}
	}
}

func platformNotificationTitle(severity string) string {
	return fmt.Sprintf("Castiel — %s", severity)
}

func escapeForPowerShell(s string) string {
	// Escape characters that could break the PowerShell command string.
	// The toast template uses CreateTextNode which handles XML escaping,
	// so we only need to escape characters that break the PowerShell string literal.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
