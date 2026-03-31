Pod::Spec.new do |s|
  s.name             = 'sibna_flutter'
  s.version          = '1.0.0'
  s.summary          = 'Flutter plugin for Sibna Protocol — Signal Protocol E2EE'
  s.description      = 'Production-grade E2EE using Signal Protocol, implemented in Rust.'
  s.homepage         = 'https://github.com/SibnaOfficial/sibna-protc'
  s.license          = { :type => 'Apache-2.0 OR MIT', :file => '../../../LICENSE' }
  s.author           = { 'Sibna Security Team' => 'security@sibna.dev' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'

  s.platform         = :osx, '10.14'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
  }
  s.swift_version    = '5.0'

  # Link the pre-built Rust static library
  s.vendored_libraries = 'libsibna.a'
end
