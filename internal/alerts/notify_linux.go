//go:build linux

package alerts

import (
	"fmt"
	"os/exec"
)

func sendPlatformNotification(title, body, severity string) {
	urgency := "normal"
	if severity == "critical" {
		urgency = "critical"
	}
	// Use notify-send (libnotify) for Linux desktop notifications
	if _, err := exec.LookPath("notify-send"); err != nil {
		// notify-send not installed — silently skip
		return
	}
	exec.Command("notify-send", "-u", urgency, title, body).Run()
}

func platformNotificationTitle(severity string) string {
	return fmt.Sprintf("Castiel — %s", severity)
}
