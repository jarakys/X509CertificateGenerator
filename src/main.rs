use rcgen::*;
use x509_parser;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;
use rustls;
use rustls::pki_types::CertificateDer;

struct X509CertificateGen {
}

impl X509CertificateGen {
    fn generate_signed_cert(
        origin_cert_der: &[u8],
        ca_cert: &Certificate,
        ca_key: &KeyPair,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let origin_cert = parse_x509_certificate(origin_cert_der)?.1;

        let mut dn = DistinguishedName::new();
        for rdn in origin_cert.tbs_certificate.subject.rdn_seq.iter() {
            for attr in rdn.set.iter() {
                let value = attr.as_str().unwrap_or("").to_string();
                match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => dn.push(DnType::CommonName, value),
                    "2.5.4.10" => dn.push(DnType::OrganizationName, value),
                    "2.5.4.6" => dn.push(DnType::CountryName, value),
                    "2.5.4.11" => dn.push(DnType::OrganizationalUnitName, value),
                    "2.5.4.7" => dn.push(DnType::LocalityName, value),
                    "2.5.4.8" => dn.push(DnType::StateOrProvinceName, value),
                    _ => {}
                }
            }
        }

        let mut subject_alt_names = vec![];
        for extension in origin_cert.tbs_certificate.iter_extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
                for name in &san.general_names {
                    subject_alt_names.push(name.to_string());
                }
            }
        }

        let mut params = CertificateParams::new(subject_alt_names)?;
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.not_before = origin_cert.validity.not_before.to_datetime();
        params.not_after = origin_cert.validity.not_after.to_datetime();
        let cert_key = KeyPair::generate()?;

        let cert1 = params.signed_by(&cert_key, &ca_cert, ca_key)?;
        let cert_der = cert1.pem();

        Ok(cert_der)
    }
}

fn main() {
    let ca_key_der = std::fs::read("src/certs/cert.der").expect("Failed to read key.der");
    let certificate_der = CertificateDer::from_slice(ca_key_der.as_slice());
    let cert = rcgen::CertificateParams::from_ca_cert_der(&certificate_der);
    let key_content = std::fs::read_to_string("src/certs/key.pem").unwrap();

    let key_pair = KeyPair::from_pem(&key_content).unwrap();
    let ca_certificate = cert.unwrap().self_signed(&key_pair);

    let origin_der = std::fs::read("src/certs/origin.der").expect("Failed to read key.der");

    let certificate = X509CertificateGen::generate_signed_cert(&origin_der, &ca_certificate.unwrap(), &key_pair);
    if let Ok(result) = certificate {
        println!("{}", result);
    }
}