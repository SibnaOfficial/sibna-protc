import FlutterMacOS

/// SibnaFlutterPlugin — macOS host-side plugin (dart:ffi plugin stub).
public class SibnaFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        // No MethodChannel needed — all calls go through dart:ffi
    }
}
