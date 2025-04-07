package log

func GetSupportedValues() [6]string {
	return [6]string{LevelTraceString, LevelDebugString, LevelInfoString, LevelWarnString, LevelErrorString, LevelFatalString}
}
