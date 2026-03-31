import Flutter
import UIKit

/// SibnaFlutterPlugin — iOS host-side plugin.
///
/// The Sibna Flutter plugin uses dart:ffi (ffiPlugin: true) for all native
/// calls. This class exists only to satisfy the Flutter plugin registry.
///
/// The native Rust library (libsibna.a) is statically linked via Xcode.
/// Build steps:
///   1. cargo build --release --target aarch64-apple-ios --features ffi
///   2. cargo build --release --target x86_64-apple-ios --features ffi
///   3. lipo -create target/aarch64-apple-ios/release/libsibna.a \
///            target/x86_64-apple-ios/release/libsibna.a \
///            -output ios/libsibna.a
public class SibnaFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        // No MethodChannel needed — all calls go through dart:ffi
    }
}
