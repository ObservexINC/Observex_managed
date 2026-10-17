//go:build windows

package supervisor

func onTerm(string) {}

func spawnChild(string) int { return 4 }

func superviseOne(string, string) int { return 5 }
