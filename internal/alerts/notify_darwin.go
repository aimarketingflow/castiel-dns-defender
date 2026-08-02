//go:build darwin

package alerts

import (
	"fmt"
	"log"
	"os/exec"
)

func sendPlatformNotification(title, body, severity string) {
	// Use osascript to display macOS notification
	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification "%s" with title "%s"`, escapeNotificationString(body), escapeNotificationString(title)))
	if err := cmd.Run(); err != nil {
		log.Printf("Desktop notification failed: %v", err)
	}
}

func platformNotificationTitle(severity string) string {
	return fmt.Sprintf("Castiel — %s", severity)
}

func escapeNotificationString(s string) string {
	return fmt.Sprintf("%q", s)
}
