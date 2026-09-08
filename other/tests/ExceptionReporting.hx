class ExceptionReporting {
	static function main():Void {
		if (Sys.args()[0] == "main") throw "main exception";
		if (Sys.args()[0] == "worker") {
			sys.thread.Thread.create(function() throw "worker exception");
			while (true) Sys.sleep(1.0);
		}
	}
}
