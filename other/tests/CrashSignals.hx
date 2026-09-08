class CrashSignals {
	static function main():Void {
		if (Sys.args()[0] == "fault") {
			CrashTestNative.fault(1);
			return;
		}
		while (true) Sys.sleep(1.0);
	}
}
