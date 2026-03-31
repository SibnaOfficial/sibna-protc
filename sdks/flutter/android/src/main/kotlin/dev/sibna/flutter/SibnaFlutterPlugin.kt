package dev.sibna.flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin

/**
 * SibnaFlutterPlugin — Android host-side plugin.
 *
 * The Sibna Flutter plugin uses dart:ffi (ffiPlugin: true) for all
 * native calls. This class exists only to satisfy the Flutter plugin
 * registry — no MethodChannel is needed.
 *
 * The native Rust library (libsibna.so) is loaded automatically by
 * the Dart FFI layer via DynamicLibrary.open('libsibna.so').
 * It must be compiled for the target ABI and placed in:
 *   android/src/main/jniLibs/<ABI>/libsibna.so
 *
 * Supported ABIs: arm64-v8a, armeabi-v7a, x86_64
 */
class SibnaFlutterPlugin : FlutterPlugin {
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // No MethodChannel needed — all calls go through dart:ffi
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // Nothing to clean up
    }
}
