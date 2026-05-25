
export type CsirtEntry = {
  name: string;
  country: string;
  contact: string | null;
  portal: string | null;
};

export const csirtContacts: Record<string, CsirtEntry> = {
  ca: {
    name: "Canadian Centre for Cyber Security (CCCS)",
    country: "CA",
    contact: "contact@cyber.gc.ca",
    portal: "https://www.cyber.gc.ca/en/incident-management"
  },
  us: {
    name: "CISA (US Cybersecurity and Infrastructure Security Agency)",
    country: "US",
    contact: "report@cisa.gov",
    portal: "https://www.cisa.gov/report"
  },
  mx: {
    name: "CERT-MX (UNAM-CERT)",
    country: "MX",
    contact: "seguridad@unam.mx",
    portal: "https://www.cert.unam.mx"
  },

  gb: {
    name: "NCSC UK (National Cyber Security Centre)",
    country: "GB",
    contact: "report@ncsc.gov.uk",
    portal: "https://www.ncsc.gov.uk/section/about-ncsc/report-an-incident"
  },
  de: {
    name: "BSI CERT-Bund (Germany)",
    country: "DE",
    contact: "certbund@bsi.bund.de",
    portal: "https://www.bsi.bund.de/EN/Topics/IT-Crisis-Management/CERT-Bund/cert-bund_node.html"
  },
  fr: {
    name: "CERT-FR (ANSSI France)",
    country: "FR",
    contact: "cert-fr@ssi.gouv.fr",
    portal: "https://www.cert.ssi.gouv.fr"
  },
  nl: {
    name: "NCSC-NL (Netherlands)",
    country: "NL",
    contact: "cert@ncsc.nl",
    portal: "https://www.ncsc.nl/contact/melden"
  },
  se: {
    name: "CERT-SE (Sweden)",
    country: "SE",
    contact: "cert@cert.se",
    portal: "https://www.cert.se/anmal-incident"
  },
  no: {
    name: "NorCERT (Norway)",
    country: "NO",
    contact: "cert@nsm.no",
    portal: "https://nsm.no/fagomrader/sikkerhetshendelse/rapporter-en-hendelse/"
  },
  fi: {
    name: "NCSC-FI (Finland)",
    country: "FI",
    contact: "cert@traficom.fi",
    portal: "https://www.kyberturvallisuuskeskus.fi/en/report"
  },
  dk: {
    name: "CFCS (Denmark)",
    country: "DK",
    contact: "cfcs@cfcs.dk",
    portal: "https://www.cfcs.dk/en/threats/report-a-cyber-incident/"
  },
  ch: {
    name: "NCSC Switzerland",
    country: "CH",
    contact: "incidents@ncsc.admin.ch",
    portal: "https://www.ncsc.admin.ch/ncsc/en/home/melden/meldung.html"
  },
  at: {
    name: "CERT.at (Austria)",
    country: "AT",
    contact: "info@cert.at",
    portal: "https://www.cert.at/de/meldung/"
  },
  be: {
    name: "CCB / CERT.be (Belgium)",
    country: "BE",
    contact: "cert@cert.be",
    portal: "https://ccb.belgium.be/en/cert"
  },
  es: {
    name: "INCIBE-CERT (Spain)",
    country: "ES",
    contact: "incibe-cert@incibe.es",
    portal: "https://www.incibe.es/en/incibe-cert/report-incident"
  },
  it: {
    name: "CSIRT Italia (ACN)",
    country: "IT",
    contact: "segnalazioni@csirt.gov.it",
    portal: "https://www.csirt.gov.it/segnala"
  },
  pl: {
    name: "CERT Polska (NASK)",
    country: "PL",
    contact: "cert@cert.pl",
    portal: "https://incydent.cert.pl"
  },
  pt: {
    name: "CNCS / CERT.PT (Portugal)",
    country: "PT",
    contact: "cert@cncs.gov.pt",
    portal: "https://www.cncs.gov.pt/en/report-an-incident/"
  },
  ie: {
    name: "NCSC Ireland",
    country: "IE",
    contact: "incidents@ncsc.gov.ie",
    portal: "https://www.ncsc.gov.ie/contact/"
  },
  ro: {
    name: "CERT-RO (Romania)",
    country: "RO",
    contact: "alerts@cert-ro.eu",
    portal: "https://dnsc.ro/raportare"
  },
  cz: {
    name: "NÚKIB / CSIRT.CZ (Czech Republic)",
    country: "CZ",
    contact: "csirt@csirt.cz",
    portal: "https://csirt.cz/en/incidents/report/"
  },
  ru: {
    name: "GOV-CERT.RU (Russia)",
    country: "RU",
    contact: "cert@gov-cert.ru",
    portal: null
  },

  au: {
    name: "ACSC (Australian Cyber Security Centre)",
    country: "AU",
    contact: "asd.assist@defence.gov.au",
    portal: "https://www.cyber.gov.au/report-and-recover/report"
  },
  nz: {
    name: "NCSC New Zealand",
    country: "NZ",
    contact: "incidents@ncsc.govt.nz",
    portal: "https://www.ncsc.govt.nz/incidents/report-an-incident/"
  },
  jp: {
    name: "JPCERT/CC (Japan)",
    country: "JP",
    contact: "info@jpcert.or.jp",
    portal: "https://www.jpcert.or.jp/english/ir/report.html"
  },
  kr: {
    name: "KrCERT/CC (South Korea)",
    country: "KR",
    contact: "cert@krcert.or.kr",
    portal: "https://www.krcert.or.kr/main.do"
  },
  cn: {
    name: "CNCERT/CC (China)",
    country: "CN",
    contact: "cncert@cert.org.cn",
    portal: "https://www.cert.org.cn/publish/english/index.html"
  },
  in: {
    name: "CERT-In (India)",
    country: "IN",
    contact: "incident@cert-in.org.in",
    portal: "https://www.cert-in.org.in/s2cMainServlet?pageid=CERTREPORT"
  },
  sg: {
    name: "SingCERT (Singapore)",
    country: "SG",
    contact: "singcert@csa.gov.sg",
    portal: "https://www.csa.gov.sg/singcert/reporting"
  },
  hk: {
    name: "HKCERT (Hong Kong)",
    country: "HK",
    contact: "hkcert@hkcert.org",
    portal: "https://www.hkcert.org/report"
  },
  tw: {
    name: "TWCERT/CC (Taiwan)",
    country: "TW",
    contact: "twcert@cert.org.tw",
    portal: "https://www.twcert.org.tw/tw/cp-134-4414-b4e49-1.html"
  },
  my: {
    name: "CyberSecurity Malaysia (MyCERT)",
    country: "MY",
    contact: "cyber999@cybersecurity.my",
    portal: "https://www.mycert.org.my/portal/report"
  },
  id: {
    name: "BSSN ID-SIRTII/CC (Indonesia)",
    country: "ID",
    contact: "report@idsirtii.or.id",
    portal: "https://idsirtii.or.id"
  },

  il: {
    name: "INCD (Israel National Cyber Directorate)",
    country: "IL",
    contact: "il-cert@gov.il",
    portal: "https://cyber.gov.il/en/report"
  },
  ae: {
    name: "UAE aeCERT",
    country: "AE",
    contact: "aecert@tra.gov.ae",
    portal: "https://www.tra.gov.ae/en/services/cyber-security.aspx"
  },
  za: {
    name: "CSIRT South Africa",
    country: "ZA",
    contact: "csirt@csirt.org.za",
    portal: "https://www.csirt.org.za/report-incident"
  },

  br: {
    name: "CERT.br (Brazil)",
    country: "BR",
    contact: "cert@cert.br",
    portal: "https://www.cert.br/contato/"
  },
  ar: {
    name: "ArCERT (Argentina)",
    country: "AR",
    contact: "arcert@jgm.gov.ar",
    portal: null
  },
  cl: {
    name: "CSIRT GOV Chile",
    country: "CL",
    contact: "csirt@interior.gov.cl",
    portal: "https://www.csirt.gob.cl/reportar-incidente/"
  },

  default: {
    name: "APWG (Anti-Phishing Working Group)",
    country: "GLOBAL",
    contact: "phishing@apwg.org",
    portal: "https://apwg.org/reportphishing/"
  }
};


export function resolveCsirt(
  registrantCountry: string | null,
  tld: string | null
): CsirtEntry {
  
  if (registrantCountry) {
    const key = registrantCountry.toLowerCase();
    if (csirtContacts[key]) {
      return csirtContacts[key];
    }
  }


  if (tld) {
    const ccKey = tld.replace(/^\./, "").toLowerCase();
  
    if (ccKey.length === 2 && csirtContacts[ccKey]) {
      return csirtContacts[ccKey];
    }
  }

  return csirtContacts.default;
}
