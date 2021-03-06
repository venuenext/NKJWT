Pod::Spec.new do |s|
  s.name         = "NKJWT"
  s.version      = "0.1.1"
  s.summary      = "NKJWT is a lightweight JSON Web Token library"

  s.description  = <<-DESC
                   NKJWT is a lightweight JSON Web Token library.
                   Easily create / update / verify tokens with a few lines of code.
                   DESC

  s.homepage     = "https://github.com/NKJWT/NKJWT"
  s.license      = "MIT"
  s.author       = "Dmitrii Ivashko"
  s.platform     = :ios, "7.0"

  s.source       = { :git => "https://github.com/NKJWT/NKJWT.git", :tag => "v#{s.version.to_s}" }

  s.source_files  = "src/**/*.{h,m}"
  s.public_header_files = "src/**/*.h"

  s.requires_arc = true

  s.dependency 'GMEllipticCurveCrypto', '~> 1.3'
end
