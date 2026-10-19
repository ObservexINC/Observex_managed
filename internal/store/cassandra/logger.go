package cassandra

import (
	"context"
	"log/slog"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// slogLogger sends the driver's log records to a slog logger, and so through
// the node's redacting handler. Debug and info records are dropped: the
// driver reports every connection event at those levels.
type slogLogger struct{ l *slog.Logger }

var _ gocql.StructuredLogger = slogLogger{}

func (s slogLogger) log(level slog.Level, msg string, fields []gocql.LogField) {
	if s.l == nil || !s.l.Enabled(context.Background(), level) {
		return
	}
	attrs := make([]slog.Attr, 0, len(fields)+1)
	attrs = append(attrs, slog.String("component", "cassandra-driver"))
	for _, f := range fields {
		attrs = append(attrs, slog.Any(f.Name, f.Value.Any()))
	}
	s.l.LogAttrs(context.Background(), level, msg, attrs...)
}

func (s slogLogger) Error(msg string, fields ...gocql.LogField)   { s.log(slog.LevelError, msg, fields) }
func (s slogLogger) Warning(msg string, fields ...gocql.LogField) { s.log(slog.LevelWarn, msg, fields) }
func (s slogLogger) Info(string, ...gocql.LogField)               {}
func (s slogLogger) Debug(string, ...gocql.LogField)              {}
