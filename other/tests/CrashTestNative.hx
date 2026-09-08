@:hlNative("crash_test")
extern class CrashTestNative {
	static function fault(address:Int):Void;
	static function stack_overflow():Void;
}
