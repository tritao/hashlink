/**
 * A call through a structure type to a method whose signature differs from the structure's goes through
 * hl_wrapper_call, which converts each argument into buffers of HL_MAX_ARGS. Twelve arguments overran them: the stack
 * cookie check ended the program on Windows (0xC0000409), and elsewhere the overrun went unnoticed.
 */
typedef Twelve = {function f(a:Int, b:Int, c:Int, d:Int, e:Int, f:Int, g:Int, h:Int, i:Int, j:Int, k:Int, l:Int):Int;};

class Impl {
	public function new() {}

	public function f(a:Dynamic, b:Dynamic, c:Dynamic, d:Dynamic, e:Dynamic, f:Dynamic, g:Dynamic, h:Dynamic, i:Dynamic,
			j:Dynamic, k:Dynamic, l:Dynamic):Int
		return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8 + i * 9 + j * 10 + k * 11 + l * 12;
}

class WrapperCallArgs {
	static function main() {
		var o:Twelve = new Impl();
		var result = o.f(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
		if (result != 78)
			throw 'expected 78, got $result';
		Sys.println("wrapped call with twelve arguments: ok");
	}
}
