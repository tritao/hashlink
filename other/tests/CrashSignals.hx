class CrashSignals {
	static function main():Void {
		if (Sys.args()[0] == "fault") {
			CrashTestNative.fault(1);
			return;
		}
		if (Sys.args()[0] == "worker-overflow") {
			sys.thread.Thread.create(CrashTestNative.stack_overflow);
			while (true) Sys.sleep(1.0);
		}
		while (true) Sys.sleep(1.0);
	}
}
