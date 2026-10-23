package etcdstore

import (
	"context"
	"log/slog"
	"sort"

	"go.uber.org/zap/zapcore"
)

// slogCore sends etcd's zap records to a slog logger, so they pass through
// the node's redacting handler like every other log line.
type slogCore struct {
	logger *slog.Logger
	min    slog.Level
	fields []zapcore.Field
}

func newSlogCore(l *slog.Logger, level slog.Level, member string) zapcore.Core {
	if l == nil {
		return zapcore.NewNopCore()
	}
	return &slogCore{logger: l.With(slog.String("component", "etcd"), slog.String("member", member)), min: level}
}

func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l <= zapcore.DebugLevel:
		return slog.LevelDebug
	case l == zapcore.InfoLevel:
		return slog.LevelInfo
	case l == zapcore.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	lv := slogLevel(l)
	return lv >= c.min && c.logger.Enabled(context.Background(), lv)
}

func (c *slogCore) With(fields []zapcore.Field) zapcore.Core {
	return &slogCore{logger: c.logger, min: c.min, fields: append(append([]zapcore.Field{}, c.fields...), fields...)}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.fields {
		f.AddTo(enc)
	}
	for _, f := range fields {
		f.AddTo(enc)
	}
	keys := make([]string, 0, len(enc.Fields))
	for k := range enc.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]slog.Attr, 0, len(keys)+1)
	if e.LoggerName != "" {
		attrs = append(attrs, slog.String("logger", e.LoggerName))
	}
	for _, k := range keys {
		attrs = append(attrs, slog.Any(k, enc.Fields[k]))
	}
	c.logger.LogAttrs(context.Background(), slogLevel(e.Level), e.Message, attrs...)
	return nil
}

func (c *slogCore) Sync() error { return nil }
